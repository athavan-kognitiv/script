import boto3
import sys

def search_and_remove_security_group_rules(ip_cidr_list, dry_run=False):
    ec2 = boto3.client('ec2')
    
    try:
        response = ec2.describe_security_groups()
        security_groups = response['SecurityGroups']
        
        for security_group in security_groups:
            existing_rules = security_group['IpPermissions']
            
            for rule in existing_rules:
                if 'IpRanges' in rule:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] in ip_cidr_list:
                            revoke_rule = {
                                'IpProtocol': rule['IpProtocol'],
                                'FromPort': rule['FromPort'],
                                'ToPort': rule['ToPort'],
                                'IpRanges': [{'CidrIp': ip_range['CidrIp']}],
                            }
                            if not dry_run:
                                ec2.revoke_security_group_ingress(
                                    GroupId=security_group['GroupId'],
                                    IpPermissions=[revoke_rule]
                                )
                            print(f"Removed rule: {revoke_rule} ", end="")
                            if 'Description' in ip_range:
                                print(f"Description: ", ip_range['Description'])
                            else:
                                print()
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == '__main__':
    ip_cidr_blocks_to_remove = [
	"12.198.132.186/32",
	"207.236.189.102/32", 
	"209.226.41.198/32", 
	"207.236.189.105/32", 
	"71.82.133.108/32",
	"116.12.189.105/32",
	"80.227.130.130/32",
	"87.200.12.23/32",
	"46.235.156.164/32",
	"87.200.12.164/32",
	"185.2.196.164/32",
	"80.169.134.64/29",
	"217.61.231.116/32",
	"217.61.231.115/32", 
	"217.61.231.116/32", 
	"217.61.231.117/32"
	]
    dry_run_mode = True
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == '--remove':
        dry_run_mode = False
    
    search_and_remove_security_group_rules(ip_cidr_blocks_to_remove, dry_run=dry_run_mode)