import configparser

import click
import keyring
import logging

from os import environ
from .prepare import create_adfs_default_config, _load_adfs_config_from_stored_profile


@click.command()
@click.option(
    '--profile',
    default=lambda: environ.get('AWS_DEFAULT_PROFILE', 'default'),
    help='AWS cli profile that will be removed'
)
@click.option(
    '--clear-keychain',
    is_flag=True,
    default=False,
    help="Reset the stored keychain credentials associated with the ADFS user"
)
def reset(profile, clear_keychain):
    """
    removes stored profile
    """
    adfs_config = create_adfs_default_config('default')
    _load_adfs_config_from_stored_profile(adfs_config, profile)

    if clear_keychain:
        _clear_keychain_credentials(adfs_config)

    _clear_credentials(adfs_config, profile)
    click.echo('Profile: \'{}\' has been wiped out'.format(profile))

def _clear_keychain_credentials(config):
    """
    Removes credentials from the keychain
    """
    try:
        if config.adfs_user:
            keyring.delete_password("aws-adfs", config.adfs_user)
            logging.debug(f"Keychain password for {config.adfs_user} wiped")
    except keyring.errors.PasswordDeleteError as delete_error:
        pass

def _clear_credentials(config, profile):
    def store_config(config_location, storer):
        config_file = configparser.RawConfigParser()
        config_file.read(config_location)

        if not config_file.has_section(profile):
            config_file.add_section(profile)

        storer(config_file)

        with open(config_location, 'w+') as f:
            try:
                config_file.write(f)
            finally:
                f.close()

    def profile_remover(config_file):
        config_file.remove_section(profile)
        config_file.remove_section('profile {}'.format(profile))

    store_config(config.aws_credentials_location, profile_remover)
    store_config(config.aws_config_location, profile_remover)
