`aws-adfs` is a command line tool that can be use Active Directory authentication in order to redeem and redeem temporary security credentials for usage with AWS.

## Installation

The tool can be installed globally or within a Python 3 virtualenv.

`pip3 install -e git+ssh://git@github.com/Multiplicom/aws-adfs.git#egg=aws-adfs awscli`

or

`python3 -m venv ~/.virtualenvs/aws && workon aws && pip install -e git+ssh://git@github.com/Multiplicom/aws-adfs.git#egg=aws-adfs awscli`

aws-adfs can be used as an external source for providing `awscli` with credentials. This will instruct `aws-adfs` to regularly redeem temporary security credentials in the background when using `awscli`.

## Usage as a Credential Provider

If you don't already have one, create a `.aws` folder in your home directory and initialize two files, a credentials file and a configuration file with the following contents:

```ini
[adfs-dev-15-developers]
credential_process = aws-adfs login
	--no-sspi
	--adfs-host=eadfs.agilent.com
  # Important: The line below needs to be changed to your personal
  # AD Username. The format is username@agilent.com or AGILENT\username
  # and is not to be mistaken for an e-mail address.
	--use-keychain=mvermeir@agilent.com
	--prompt=osascript
	--role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-developers
	--profile=adfs-dev-15-developers
	--stdout
```

_Example ~/.aws/credentials file with aws-adfs as an external credentials provider_

Next, initialize the `config` file with the following values:
```ini
[default]
source_profile = adfs-dev-15-developers
region = eu-west-3
role_arn = arn:aws:iam::775874812736:role/agilent-aws-dev-15-developers

[profile adfs-dev-15-developers]
region = eu-west-3
output = json
```

_Example ~/.aws/config with the default profile assuming a different role based on another profile_

Now try it out by running `aws sts get-caller-identity`. If this is your first time, running this command, you
will be prompted several times:

First you need to approve the `aws-adfs` tool to access the macOS keychain. The keychain is the place where the tool
securely stores your AD password, so it can't be inadvertently shared with another party that gains access to your 
computer.

Enter the password to unlock your macOS keychain, which is usually your AD passsword, an click _Always allow_.

Next, you will see a prompt for your terminal to access the system events. Clicking _Allow_, allows
the `aws-adfs` tool to prompt you for your AD password if it didn't find it in the keychain without 
interrupting the process sourcing the credentials.

Lastly, you will see the password prompt if this is your first time using the tool. Now you can use the aws CLI tool
without being prompted for your AD password. 

```
$ aws s3 ls
2018-04-26 10:37:31 agilent-aws-dev-15
2018-08-16 15:41:11 agilent-aws-dev-15-dev-backup
2019-08-22 14:50:02 agilent-aws-dev-15-dev-build
2018-09-10 13:38:57 agilent-aws-dev-15-dev-cldev-backup
2019-11-04 08:02:46 agilent-aws-dev-15-dev-eu-west-1-dragen
2019-07-29 09:04:16 agilent-aws-dev-15-eu-west-3-import
2018-11-20 11:56:57 agilent-aws-dev-15-flow-logs
2019-07-17 11:38:04 agilent-aws-dev-15-transfer
2019-10-14 14:50:11 build-notification-handl-serverlessdeploymentbuck-1czi38olwwcic
2019-10-09 11:49:53 cf-templates-jynao21735q3-eu-west-3
2018-11-22 16:16:52 codebuild-aws-dev-15
2019-09-16 13:57:19 mr-lasergen-agilent-aws-dev-15
2019-09-06 09:12:19 mr-space-agilent-aws-dev-15
2019-04-15 08:31:08 mr-storage-eu-west-3-agilent-aws-dev-15
2018-11-06 09:02:27 mr17-011-dev-15
2018-12-18 16:05:24 mr19-internal-dev-15
```

### Updating your AD password
If your AD password expired or you recently changed your password, you might see the following error:

> Error when retrieving credentials from custom-process: This account does not have access to any roles

In that case, what you need to do is open the macOS keychain, look for the entry called **aws-adfs** and delete it. Run the aws command again to be prompted for your updated AD password.


## Troubleshooting

If you get the following error message:
> Error when retrieving credentials from custom-process: This account does not have access to any roles

There are two possible causes and solution:
1. Either your AD password is wrong or might have changed. See the section on _Updating your AD password_ on how you can reset it.
2. You are not connected to the Agilent network. Either make sure you are on the spark network or connect with the VPN.
