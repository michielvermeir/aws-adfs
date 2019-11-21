`aws-adfs` is a command line tool that can be use Active Directory authentication in order to redeem and redeem temporary security credentials for usage with AWS.

## Installation
The tool can be installed globally or within a Python 3 virtualenv.

`pip3 install -e git+ssh://git@github.com/Multiplicom/aws-adfs.git#egg=aws-adfs awscli`

or 

`python3 -m venv ~/.virtualenvs/aws && workon aws && pip install -e git+ssh://git@github.com/Multiplicom/aws-adfs.git#egg=aws-adfs awscli`

aws-adfs can be used as an external source for providing `awscli` with credentials. This will instruct `aws-adfs` to regularly redeem temporary security credentials in the background when using `awscli`. 

## First-Time Authentication
In order to not have to prompt you for you password in this mode, the first authentication has to happen manually. The tool will prompt you for you AD user and password. It will securely store the AD password in the OS keychain for reuse later.

```bash
$ aws-adfs login \                                                              
    --no-sspi \
    --use-keychain \
    --adfs-host=eadfs.agilent.com \
    --role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-user \
    --profile=adfs

Username: mvermeir@agilent.com 
Password: ********

        Prepared ADFS configuration as follows:
            * AWS CLI profile                   : 'adfs'
            * AWS region                        : 'eu-central-1'
            * Output format                     : 'json'
            * SSL verification of ADFS Server   : 'ENABLED'
            * Selected role_arn                 : 'arn:aws:iam::057324062129:role/agilent-aws-dev-15-user'
            * ADFS Server                       : 'eadfs.agilent.com'
            * ADFS Session Duration in seconds  : '7200'
            * Provider ID                       : 'urn:amazon:webservices'
            * S3 Signature Version              : 'None'
            * STS Session Duration in seconds   : '3600'
            * SSPI:                             : 'False'
            * U2F and default method            : 'Tru
```
_Example command for first time authentication._


## Usage as a Credential Provider
If you don't already have one, create a `.aws` folder in your home directory and initialize a config file.

```ini
[default]
default_region = "eu-west-3" # Paris
credential_process = aws-adfs login
  --no-sspi
  --use-keychain
  --adfs-user=<ad-username>@agilent.com 
  --adfs-host=eadfs.agilent.com
  --role-arn=arn:aws:iam::057324062129:role/agilent-aws-dev-15-user
  --role-chaining-role-arn=arn:aws:iam::775874812736:role/agilent-aws-dev-15-user
  --profile=adfs
  --stdout
```

_Example ~/.aws/config file with aws-adfs as an external credentials provider_

Now try it out by using the `awscli`.
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