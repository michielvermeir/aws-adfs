# Managing multiple Roles and Accounts

If you're managing multiple roles and multiple accounts, the configuration for `aws` can quickly devolve into a hot mess. 

Every role requires at least
* a piece of configuration in the credentials file to source credentials from `aws-adfs`, and on top of that,
* two profiles in the config file, one for the role on the IAM account, and one for the role on the actual target account.


The reason for this is that, assuming the final, desired role on the target AWS account is always a 3 step process.

<dl>
  <dt><strong>Federated Authentication</strong></dt>
  <dd>The user must successfully authenticate with Active Directory Federation Services. This results in the ADFS server responding with a list of all the roles that user is entitled to in an XML document called a SAML response.</dd>

  <dt><strong>IAM Account Authentication</strong></dt>
  <dd>The response from ADFS needs to be exchanged for valid AWS Credentials. A trust relationship has been established between AD server and the IAM Account on AWS. This means the IAM Account is configured to trust SAML responses that were cryptographically signed by ADFS. However, these temporary credentials only give very limited permissions on the IAM Account, in this case, to assume another role on another account and nothing more.</dd>

  <dt><strong>Assuming Roles and Switching Accounts</strong></dt>
  <dd>Using the AWS Credentials acquired earlier, the user can finally assume the desired role in the target account.</dd>
</dl>


## Example config
Suppose you are switching often between the following roles by passing through the IAM Account:

| agilent-aws-iam-01                | 057324062129 |
|-----------------------------------|--------------|
| agilent-aws-dev-15-developers     | 775874812736 |
| agilent-aws-dev-15-devops         | 775874812736 |
| agilent-aws-prd-15-devops         | 824799901001 |

These two roles (developer and devops) span two different AWS accounts (dev-15 and prd-15). 

The **credentials file** needs to be bootstrapped for federated authentication using Active Directory by using the `aws-adfs` tool as a credentials provider. Add a section for every role, you are never to use them directly.

```ini
[adfs-dev-15-developers]
credential_process = aws-adfs login
	--no-sspi
	--adfs-host=eadfs.agilent.com
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-developers
	--use-keychain=mvermeir@agilent.com 
	--profile=adfs-dev-15-developers
	--stdout

[adfs-dev-15-devops]
credential_process = aws-adfs login
	--no-sspi
	--adfs-host=eadfs.agilent.com
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-devops
	--use-keychain=mvermeir@agilent.com
	--profile=adfs-dev-15-devops
	--stdout

[adfs-prd-15-devops]
credential_process = aws-adfs login
	--no-sspi
	--adfs-host=eadfs.agilent.com
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-prd-15-devops
	--use-keychain=mvermeir@agilent.com
	--profile=adfs-prd-15-devops
```
_~/.aws/credentials_

Then, as for the **config file**, first add a profile for every section in the credentials file. It needs to have the same name as the corresponding section in credentials and the name for the `--profile` argument as defined in the credentials file. These profiles are for storing additional metadata and will also serve as the source profiles when assuming roles:

```ini
[profile adfs-dev-15-developers]
region = eu-west-3
output = json

[profile adfs-dev-15-devops]
region = eu-west-3
output = json

[profile adfs-prd-15-devops]
region = eu-west-3
output = json
```
_~/.aws/config_

Next, add a profile for every role in the target account using the `role_arn` and ensure that the `source_profile` is set to the corresponding adfs profile. This is important, as it allows you to assume the final, desired role on the target account, by using a different profile and sourcing your credentials using the `aws-adfs` tool.

```ini
[profile developer@dev]
source_profile = adfs-dev-15-developers
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-developers

[profile devops@dev]
source_profile = adfs-dev-15-devops
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-devops

[profile devops@prd]
source_profile = adfs-prd-15-devops
region = eu-west-3
role_arn = arn:aws:iam::824799901001:role/agilent-aws-prd-15-user
```
_~/.aws/config_

Using this approach, it becomes trivial to switch between roles using by setting the `AWS_PROFILE` environment variable or by passing the `--profile` param to the AWS CLI: `AWS_PROFILE=developer@dev aws sts get-caller-identity` or `aws --profile=devops@dev sts get-caller-identity`.

Now, if you use one of these profiles more than the other, it is also trivial to add a default profile that will be used if no other profile is selected:

```ini
[default]
source_profile = adfs-dev-15-devops
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-devops
```
_~/.aws/config_

