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


## Example Configuration
Suppose you are switching often between the following roles by passing through the IAM Account:

| agilent-aws-iam-01                | 057324062129 |
|-----------------------------------|---|
| agilent-aws-dev-15-developers     | 775874812736 |
| agilent-aws-dev-15-devops         | 775874812736 |
| agilent-aws-prd-15-devops         | 824799901001 |

These two roles (developer and devops) span two different AWS accounts (dev-15 and prd-15). 

### The credentials file
The credentials file first needs to be bootstrapped for federated authentication using Active Directory by sourcing AWS credentials using the `aws-adfs` tool. There are a couple of things to note in order to understand what is going on, best explained by going over the individual items.

Notice that there is a section in the credentials for each and every of the roles in table. The naming convention `adfs-$SHORT_ROLE_NAME` was picked for clarity and for adding predictability into the naming. Also notice that the initial Role ARN here corresponds to a role of the same name in the IAM Account. Additionally, the `AWS_PROFILE` is given the same exact same name as the section in the credentials file. And finally, notice that the param passed to `--use-keychain` is 


```ini
[default]
region = eu-west-3

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
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-ops
	--use-keychain=mvermeir@agilent.com
	--profile=adfs-dev-15-devops
	--stdout

[adfs-prd-15-devops]
credential_process = aws-adfs login
	--no-sspi
	--adfs-host=eadfs.agilent.com
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-prd-15-ops
	--use-keychain=mvermeir@agilent.com
	--profile=adfs-prd-15-devops
```
_Example `~/.aws/credentials` file for multi-role multi-account scenarios_


### The config file
```ini
[profile developer@dev-15]
source_profile = adfs-dev-15-developers
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-developers

[profile admin@dev-15]
source_profile = adfs-dev-15-user
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-user

[profile admin@tst-15]
source_profile = adfs-tst-15-user
region = eu-west-3
role_arn = arn:aws:iam::790662393407:role/agilent-aws-tst-15-user

[profile admin@prd-15]
source_profile = adfs-prd-15-user
region = eu-west-3
role_arn = arn:aws:iam::824799901001:role/agilent-aws-prd-15-user

[profile adfs-dev-15-developers]
region = eu-west-3
output = json

[profile adfs-dev-15-user]
region = eu-west-3
output = json

[profile adfs-tst-15-user]
region = eu-west-3
output = json

[profile adfs-prd-15-user]
region = eu-west-3
output = json
```