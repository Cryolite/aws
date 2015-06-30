#!/usr/bin/env python

import boto.vpc
import gflags
import logging
import subprocess
import tempfile
import time
import re
import sys
import shutil
import os.path
import os

FLAGS = gflags.FLAGS

gflags.DEFINE_string('access_key_id', None, 'Access Key ID')
gflags.DEFINE_string('secret_access_key', None, 'Secret Access Key')
gflags.DEFINE_string('elastic_ip', None, 'Elastic IP')
gflags.DEFINE_bool('boto_verbose', False, '')
gflags.DEFINE_bool('verbose', False, '')
gflags.MarkFlagAsRequired('access_key_id')
gflags.MarkFlagAsRequired('secret_access_key')
gflags.MarkFlagAsRequired('elastic_ip')

REGION = 'ap-northeast-1'
VPC_NAME_TAG = 'Main_VPC'
SUBNET_NAME_TAG = 'Main_NAPT_Subnet'
SECURITY_GROUP_NAMES = ['main-napt']
CLIENT_TOKEN = 'net.cryolite.aws.tokyo.main.napt'
SPOT_PRICE = '0.005'
IMAGE_ID = 'ami-c7e016c7' # amzn-ami-vpc-nat-pv-2015.03.0.x86_64-ebs
INSTANCE_TYPE = 't1.micro'
KEY_PAIR_NAME = 'cryolite@aquamarine-ubuntu.cryolite.net'
INSTANCE_NAME_TAG = 'Main_NAPT'
SSH_LOGIN_NAME = 'ec2-user'
ROUTE_TABLE_IDS = ['rtb-87842ce2', 'rtb-34953d51']

def initialize(argv):
    FLAGS(argv)
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d %(levelname)s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    boto.set_stream_logger('boto')
    if FLAGS.boto_verbose == True:
        logging.getLogger('boto').setLevel(logging.DEBUG)
    else:
        logging.getLogger('boto').setLevel(logging.INFO)
    my_logger = logging.getLogger('net.cryolite.aws')
    if FLAGS.verbose == True:
        my_logger.setLevel(logging.DEBUG)
    else:
        my_logger.setLevel(logging.INFO)

class ElasticIpAddressUpdateFailure(Exception):
    def __init__(self): pass

def update_elastic_ip_address(ec2_connection, eip):
    eip = filter(lambda e: e.public_ip == eip.public_ip, ec2_connection.get_all_addresses())
    if len(eip) == 0:
        raise ElasticIpAddressUpdateFailure()
    if len(eip) > 1:
        raise ElasticIpAddressUpdateFailure()
    return eip[0]

class CommandError(Exception):
    def __init__(self, cmd, returncode, stdoutdata, stderrdata):
        self.cmd = cmd
        self.returncode = returncode
        self.stdoutdata = stdoutdata
        self.stderrdata = stderrdata

def execute_command(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdoutdata, stderrdata = popen.communicate()
    if popen.returncode != 0:
        raise CommandError(
            cmd=cmd, returncode=popen.returncode, stdoutdata=stdoutdata, stderrdata=stderrdata)
    return (stdoutdata, stderrdata)

def main(argv):
    initialize(argv)
    my_logger = logging.getLogger('net.cryolite.aws')
    vpc_connection = boto.vpc.connect_to_region(REGION,
                                                aws_access_key_id=FLAGS.access_key_id,
                                                aws_secret_access_key=FLAGS.secret_access_key)
    my_logger.info('created a VPC connection to the region `%s\'', REGION)
    vpc = filter(lambda v: ('Name' in v.tags) and (v.tags['Name'] == VPC_NAME_TAG),
                 vpc_connection.get_all_vpcs())
    if len(vpc) == 0:
        my_logger.error('could not find any VPC with the name tag `%s\'', VPC_NAME_TAG)
        return 1
    if len(vpc) > 1:
        my_logger.error('found multiple VPCs `%s\' with the name tag `%s\'',
                        str([v.id for v in vpc]),
                        VPC_NAME_TAG)
        return 1
    vpc = vpc[0]
    my_logger.info('found the unique VPC `%s\' with the name tag `%s\'', vpc.id, VPC_NAME_TAG)
    if vpc.state != 'available':
        my_logger.error('the State of the VPC `%s\' is '
                        'expected to be `available\', but is `%s\'',
                        vpc.id,
                        vpc.state)
        return 1
    subnet = filter(lambda s: ('Name' in s.tags) and (s.tags['Name'] == SUBNET_NAME_TAG),
                    vpc_connection.get_all_subnets())
    if len(subnet) == 0:
        my_logger.error('could not find the Subnet with the name tag `%s\'', SUBNET_NAME_TAG)
        return 1
    if len(subnet) > 1:
        my_logger.error('found multiple Subnets `%s\' with the name tag `%s\'',
                        str([s.id for s in subnet]),
                        SUBNET_NAME_TAG)
        return 1
    subnet = subnet[0]
    my_logger.info('found the unique Subnet `%s\' with the name tag `%s\'',
                   subnet.id,
                   SUBNET_NAME_TAG)
    if subnet.state != 'available':
        my_logger.error('the State of the Subnet `%s\' is '
                        'expected to be `available\', but is `%s\'',
                        subnet.id,
                        subnet.state)
        return 1
    if subnet.vpc_id != vpc.id:
        my_logger.error('the Subnet `%s\' is expected to be '
                        'in the VPC `%s\', but in the VPC `%s\'',
                        subnet.id,
                        vpc.id,
                        subnet.vpc_id)
        return 1
    if subnet.available_ip_address_count == 0:
        my_logger.error('there is no available IP address in the Subnet `%s\'', subnet.id)
        return 1
    if subnet.mapPublicIpOnLaunch == True:
        my_logger.error('refuse the Subnet `%s\' '
                        'because instances launched in this Subnet receive a public IP address',
                        subnet.id)
        return 1
    ec2_connection = boto.ec2.connect_to_region(REGION,
                                                aws_access_key_id=FLAGS.access_key_id,
                                                aws_secret_access_key=FLAGS.secret_access_key)
    my_logger.info('created an EC2 connection to the region `%s\'', REGION)
    security_groups = []
    sgs = ec2_connection.get_all_security_groups()
    for sg_name in SECURITY_GROUP_NAMES:
        security_group = filter(lambda sg: sg.name == sg_name, sgs)
        if len(security_group) == 0:
            my_logger.error('could not find the Security Group with the name `%s\'', sg_name)
            return 1
        if len(security_group) > 1:
            my_logger.error('found multiple Security Groups `%s\' with the name `%s\'',
                            str([sg.name for sg in security_group]),
                            sg_name)
            return 1
        security_groups.extend(security_group)
    my_logger.info('found the Security Groups `%s\'', str([sg.name for sg in security_groups]))
    for sg in security_groups:
        if sg.vpc_id != vpc.id:
            my_logger.error('the Security Group `%s\' is expected to be '
                            'for the VPC `%s\', but for the VPC `%s\'',
                            sg.name,
                            vpc.id,
                            sg.vpc_id)
            return 1
    eip = filter(lambda eip: eip.public_ip == FLAGS.elastic_ip,
                 ec2_connection.get_all_addresses())
    if len(eip) == 0:
        my_logger.error('could not find the Elastic IP `%s\'', FLAGS.elastic_ip)
        return 1
    if len(eip) > 1:
        my_logger.error('found multiple Elastic IPs `%s\'', str([e.public_ip for e in eip]))
        return 1
    eip = eip[0]
    my_logger.info('found the Elastic IP `%s\'', eip.public_ip)
    if eip.instance_id is not None:
        my_logger.error('the Elastic IP `%s\' has been already associated to the Instance `%s\'',
                        eip.public_ip,
                        eip.instance_id)
        return 1
    my_logger.info('the Elastic IP `%s\' is available', eip.public_ip)
    key_pair = ec2_connection.get_key_pair(KEY_PAIR_NAME)
    if key_pair is None:
        my_logger.error('could not find the Key Pair with the name `%s\'', KEY_PAIR_NAME)
        return 1
    my_logger.info('found the Key Pair with the name `%s\'', key_pair.name)
    spot_instance_request = ec2_connection.request_spot_instances(
        SPOT_PRICE,
        IMAGE_ID,
        key_name=key_pair.name,
        security_group_ids=[sg.id for sg in security_groups],
        instance_type=INSTANCE_TYPE,
        subnet_id=subnet.id)
    if len(spot_instance_request) == 0:
        my_logger.error('no Spot Instance Request created')
        return 1
    if len(spot_instance_request) > 1:
        my_logger.error('mistakenly created multiple Spot Instance Requests `%s\'',
                        str([sir.id for sir in spot_instance_request]))
        my_logger.critical('the Spot Instance Requests `%s\' are left `open\' or `active\', '
                           'and there might be associated Instances left `running\'',
                           str([sir.id for sir in spot_instance_request]))
        return 2
    spot_instance_request = spot_instance_request[0]
    my_logger.info('created a Spot Instance Request `%s\'', spot_instance_request.id)
    if str(spot_instance_request.price) != SPOT_PRICE:
        my_logger.error('the Spot Price for the Spot Instance Request `%s\' is `%s\', '
                        'which differs from the specified one `%s\'',
                        spot_instance_request.id,
                        spot_instance_request.price,
                        SPOT_PRICE)
        my_logger.critical('the Spot Instance Request `%s\' is left `open\' or `active\', '
                           'and there might be an associated Instance left `running\'',
                           spot_instance_request.id)
        return 2
    while spot_instance_request.state == 'open':
        my_logger.info('the State of the Spot Instance Request `%s\' is still `open\', '
                       'waiting for a minute...',
                       spot_instance_request.id)
        time.sleep(60)
        spot_instance_request = ec2_connection.get_all_spot_instance_requests(
            [spot_instance_request.id])
        if len(spot_instance_request) != 1:
            my_logger.error('failed to update the Spot Instance Request `%s\'',
                            spot_instance_request.id)
            my_logger.critical('the Spot Instance Request `%s\' is left `open\' or `active\', '
                               'and there might be an associated Instance left `running\'',
                               spot_instance_request.id)
            return 2
        spot_instance_request = spot_instance_request[0]
    if spot_instance_request.state != 'active':
        my_logger.error('the State of the Spot Instance Request `%s\' is '
                        'expected to be `active\', but is `%s\'',
                        spot_instance_request.id,
                        spot_instance_request.state)
        if spot_instance_request.instance_id is not None:
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               spot_instance_request.instance_id)
            return 2
        return 1
    my_logger.info('the State of the Spot Instance Request `%s\' is now `active\'',
                   spot_instance_request.id)
    instance_id = spot_instance_request.instance_id
    if instance_id is None:
        my_logger.error('failed to identify the Instance associated '
                        'with the Spot Instance Request `%s\'',
                        spot_instance_request.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\'',
                           spot_instance_request.id)
        return 2
    # the call to `get_only_instances` in the following line should be replaced
    # with `get_all_instances` in the future
    instance = ec2_connection.get_only_instances([instance_id])
    if len(instance) == 0:
        my_logger.error('failed to identify the Instance associated '
                        'with the Spot Instance Request `%s\'',
                        spot_instance_request.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\'',
                           spot_instance_request.id)
        return 2
    if len(instance) > 1:
        my_logger.error('failed to identify the Instance associated '
                        'with the Spot Instance Request `%s\'',
                        spot_instance_request.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and associated Instances `%s\' are left running',
                           spot_instance_request.id,
                           str([i.id for i in instance]))
        return 2
    instance = instance[0]
    if instance.id != spot_instance_request.instance_id:
        my_logger.error('the Instance ID of the Spot Request Instance `%s\' is `%s\', '
                        'but the ID of the launched Instance is `%s\'',
                        spot_request_instance.id,
                        spot_request_instance.instance_id,
                        instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and Instances `%s\' are left `running\'',
                           spot_request_instance.id,
                           str([spot_instance_request.instance_id, instance.id]))
    if instance.state != 'pending' and instance.state != 'running':
        my_logger.error('the state of the Instance `%s\' is expected '
                        'to be `pending\' or `running\', but is `%s\'',
                        instance.id,
                        instance.state)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.key_name != key_pair.name:
        my_logger.error('the name of the SSH key associated with the Instance `%s\' is '
                        'expected to be `%s\', but is `%s\'',
                        instance.id,
                        key_pair.name,
                        instance.key_name)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.instance_type != INSTANCE_TYPE:
        my_logger.error('the Instance Type of the Instance `%s\' is expected to be `%s\', '
                        'but is `%s\'',
                        instance.id,
                        INSTANCE_TYPE,
                        instance.instance_type)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.image_id != IMAGE_ID:
        my_logger.error('the Image ID of the Instance `%s\' is expected to be `%s\', '
                        'but is `%s\'',
                        instance.id,
                        IMAGE_ID,
                        instance.image_id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.spot_instance_request_id != spot_instance_request.id:
        my_logger.error('the Spot Instance Request ID of the Instance `%s\' is '
                        'expected to be `%s\', but is `%s\'',
                        instance.id,
                        spot_instance_request.id,
                        instance.spot_instance_request_id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.subnet_id != subnet.id:
        my_logger.error('the Subnet ID of the Instance `%s\' is expected to be `%s\', '
                        'but is `%s\'',
                        instance.id,
                        subnet.id,
                        instance.subnet_id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.vpc_id != vpc.id:
        my_logger.error('the VPC ID of the Instance `%s\' is expected to be `%s\', '
                        'but is `%s\'',
                        instance.id,
                        vpc.id,
                        instance.vpc_id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if instance.ip_address is not None:
        my_logger.error('the Instance `%s\' has received a global IP address `%s\', '
                        'but it is not allowed',
                        instance.id,
                        instance.ip_address)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('Instance ID: %s', instance.id)
    my_logger.info('AMI Launch Index: %s', instance.ami_launch_index)
    my_logger.info('AMI ID: %s', instance.image_id)
    my_logger.info('Instance Type: %s', instance.instance_type)
    my_logger.info('Kernel ID: %s', instance.kernel)
    my_logger.info('Key Pair Name: %s', instance.key_name)
    my_logger.info('Launch Time: %s', instance.launch_time)
    my_logger.info('Monitoring: %s', instance.monitored)
    my_logger.info('Placement: %s', instance.placement)
    my_logger.info('Platform: %s', instance.platform)
    my_logger.info('Private DNS Name: %s', instance.private_dns_name)
    my_logger.info('Private IP Address: %s', instance.private_ip_address)
    my_logger.info('Product Codes: %s', instance.product_codes)
    my_logger.info('Public DNS Name: %s', instance.public_dns_name)
    my_logger.info('Public IP Address: %s', instance.ip_address)
    my_logger.info('RAM Disk ID: %s', instance.ramdisk)
    my_logger.info('State: %s', instance.state)
    my_logger.info('State Transition Reason: %s', instance.state_reason)
    my_logger.info('Subnet ID: %s', instance.subnet_id)
    my_logger.info('VPC ID: %s', instance.vpc_id)
    my_logger.info('Architecture: %s', instance.architecture)
    my_logger.info('Block Device Mappings: %s', instance.block_device_mapping)
    my_logger.info('EBS Optimized: %s', instance.ebs_optimized)
    my_logger.info('Hypervisor: %s', instance.hypervisor)
    my_logger.info('IAM Instance Profile: %s', instance.instance_profile)
    my_logger.info('Network Interfaces: %s', instance.interfaces)
    my_logger.info('Root Device Name: %s', instance.root_device_name)
    my_logger.info('Root Device Type: %s', instance.root_device_type)
    my_logger.info('Security Groups: %s', str([sg.name for sg in instance.groups]))
    my_logger.info('Source Dest Check: %s',
                   ec2_connection.get_instance_attribute(instance.id, 'sourceDestCheck'))
    my_logger.info('Spot Instance Request ID: %s', instance.spot_instance_request_id)
    my_logger.info('Sriov Net Support: %s',
                   ec2_connection.get_instance_attribute(instance.id, 'sriovNetSupport'))
    my_logger.info('Tags: %s', instance.tags)
    my_logger.info('Virtualization Type: %s', instance.virtualization_type)
    while instance.state == 'pending':
        my_logger.info('the State of the Instance `%s\' is still `pending\', '
                       'waiting for a minute...',
                       instance.id)
        time.sleep(60)
        # the call to `get_only_instances` in the following line should be replaced
        # with `get_all_instances` in the future
        instance = ec2_connection.get_only_instances([instance.id])
        if len(instance) != 1:
            my_logger.error('failed to update the Instance `%s\'', instance.id)
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               instance.id)
            return 2
        instance = instance[0]
    if instance.state != 'running':
        my_logger.error('the State of the Instance `%s\' is expected to `running\', '
                        'but is `%s\'',
                        instance.id,
                        instance.state)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('the State of the Instance `%s\' is now `running\'', instance.id)
    console_output = instance.get_console_output()
    while console_output.output is None:
        my_logger.info('the Console Output of the Instance `%s\' is not available, '
                       'waiting for a minute...',
                       instance.id)
        time.sleep(60)
        console_output = instance.get_console_output()
    my_logger.info('the Console Output of the Instance `%s\' is now available', instance.id)
    my_logger.debug(console_output.output)
    public_key_match_in_console_output = re.compile(
        u'ecdsa-sha2-nistp256 [+/0-9=A-Za-z]*').search(console_output.output)
    if public_key_match_in_console_output is None:
        my_logger.error('could not find any public key '
                        'in the Console Output of the Instance `%s\'',
                        instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    public_key = public_key_match_in_console_output.group(0)
    my_logger.info('the SSH public key of the Instance `%s\' is `%s\'', instance.id, public_key)
    if eip.associate(instance.id) != True:
        my_logger.error('failed to associate the Elastic IP `%s\' with the Instance `%s\'',
                        eip.public_ip,
                        instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    instance.update()
    eip = update_elastic_ip_address(ec2_connection, eip)
    if instance.ip_address != eip.public_ip or instance.id != eip.instance_id:
        my_logger.error('failed to associate the Elastic IP `%s\' with the Instance `%s\'',
                        eip.public_ip,
                        instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('associated the Elastic IP `%s\' with the Instance `%s\'',
                   eip.public_ip,
                   instance.id)
    while True:
        try:
            stdoutdata, stderrdata = execute_command(['ssh-keyscan', '-t', 'ecdsa', eip.public_ip])
        except CommandError as e:
            my_logger.error('failed to verify the public key of the Instance `%s\', instance.id')
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               instance.id)
            return 2
        if stdoutdata:
            break
        my_logger.info('verifying the public key of the Instance `%s\', waiting for a minute...',
                       instance.id)
        time.sleep(60)
    if stdoutdata.rstrip() != '{0} {1}'.format(instance.ip_address, public_key):
        my_logger.error('failed to verify the public key of the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('verified the public key of the Instance `%s\'', instance.id)
    _, tempfile_ph = tempfile.mkstemp()
    with open(tempfile_ph, 'w') as f:
        f.write('{0} {1}\n'.format(instance.ip_address, public_key))
    try:
        execute_command(['ssh-keygen', '-Hf', tempfile_ph])
    except CommandError as e:
        my_logger.error('failed to hash the file `%s\'', tempfile_ph)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'the associated Instance `%s\' is left `running\', '
                           'and the temporary file `%s\' is left unremoved',
                           spot_instance_request.id,
                           instance.id,
                           tempfile_ph)
        return 2
    os.remove('{0}.old'.format(tempfile_ph))
    try:
        execute_command(['ssh-keygen', '-R', instance.ip_address])
    except CommandError as e:
        my_logger.error('failed to remove keys belonging to the Elastic IP Address `%s\' '
                        'from the file `~/.ssh/known_hosts\'',
                        instance.ip_address)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'the associated Instance `%s\' is left `running\', '
                           'and the temporary file `%s\' is left unremoved',
                           spot_instance_request.id,
                           instance.id,
                           tempfile_ph)
        return 2
    with open(tempfile_ph, 'r') as f:
        with open(os.path.expanduser('~/.ssh/known_hosts'), 'a') as known_hosts_file:
            shutil.copyfileobj(f, known_hosts_file)
    os.remove(tempfile_ph)
    try:
        stdoutdata, _ = execute_command(['ssh', '-l', SSH_LOGIN_NAME, instance.ip_address, 'whoami'])
    except CommandError as e:
        my_logger.error('failed to login to the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    if stdoutdata.rstrip() != SSH_LOGIN_NAME:
        my_logger.error('failed to login to the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('verified to login to the Instance `%s\'', instance.id)
    my_logger.info('updating every installed package on the Instance `%s\', '
                   'waiting for a minute...',
                   instance.id)
    try:
        execute_command(
            ['ssh', '-t', '-t', '-l', SSH_LOGIN_NAME, instance.ip_address, 'sudo', 'yum', '-y', 'update'])
    except CommandError as e:
        my_logger.error('failed to update any installed package on the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('updated every installed package on the Instance `%s\'', instance.id)
    try:
        execute_command(
            ['ssh', '-t', '-t', '-l', SSH_LOGIN_NAME, instance.ip_address, 'sudo', 'reboot'])
    except CommandError as e:
        my_logger.error('failed to reboot the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    time.sleep(10)
    while True:
        try:
            stdoutdata, _ = execute_command(
                ['ssh', '-t', '-t', '-l', SSH_LOGIN_NAME, instance.ip_address, 'whoami'])
            if stdoutdata.rstrip() == SSH_LOGIN_NAME:
                break
            my_logger.error('failed to reboot the Instance `%s\'', instance.id)
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               instance.id)
            return 2
        except CommandError as e:
            pass
        my_logger.info('rebooting the Instance `%s\', waiting for a minute...', instance.id)
        time.sleep(60)
    my_logger.info('rebooted the Instance `%s\'', instance.id)
    instance.modify_attribute('sourceDestCheck', False)
    instance.update()
    instance_attribute = instance.get_attribute('sourceDestCheck')
    if 'sourceDestCheck' not in instance_attribute or instance_attribute['sourceDestCheck'] != False:
        my_logger.error('failed to disable Source/Destination Check for the Instance `%s\'',
                        instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('disabled Source/Destination Check for the Instance `%s\'', instance.id)
    instance.add_tag('Name', INSTANCE_NAME_TAG)
    if instance.tags['Name'] != INSTANCE_NAME_TAG:
        my_logger.error('failed to add the tag `Name\' to the Instance `%s\'', instance.id)
        my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                           'and the associated Instance `%s\' is left `running\'',
                           spot_instance_request.id,
                           instance.id)
        return 2
    my_logger.info('added the tag `Name\' with the value `%s\' to the Instance `%s\'',
                   INSTANCE_NAME_TAG,
                   instance.id)
    for route_table_id in ROUTE_TABLE_IDS:
        if vpc_connection.delete_route(route_table_id, '0.0.0.0/0') != True:
            my_logger.error('failed to delete a default route (destined to 0.0.0.0/0) '
                            'in the Route Table `%s\'',
                            route_table_id)
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               instance.id)
            return 2
        my_logger.info('deleted a default route (destined to 0.0.0.0/0) '
                       'in the Route Table `%s\'',
                       route_table_id)
        if vpc_connection.create_route(route_table_id, '0.0.0.0/0', instance_id=instance.id) != True:
            my_logger.error('failed to create a default route (destined to 0.0.0.0/0) '
                            'to the Instance `%s\' in the Route Table `%s\'',
                            instance.id,
                            route_table_id)
            my_logger.critical('the Spot Instance Request `%s\' is left `active\', '
                               'and the associated Instance `%s\' is left `running\'',
                               spot_instance_request.id,
                               instance.id)
            return 2
        my_logger.info('created a default route (destined to 0.0.0.0/0) '
                       'to the Instance `%s\' in the Route Table `%s\'',
                       instance.id,
                       route_table_id)
    my_logger.info('completed deployment of the Instance `%s\'', instance.id)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
sys.exit(1)
