
from collections import namedtuple

ARN = namedtuple(
    "ARN", [
        "partition",
        "service",
        "region",
        "account_id",
        "resource_type",
        "resource_id",
    ]
)


class InvalidARNError(Exception):
    pass


def parse_arn(arn):
    (
        _,  # arn
        partition,
        service,
        region,
        account_id,
        *resource
    ) = arn.split(":")

    if len(resource) < 2:
        resource = resource[0]
        if "/" in resource:
            (resource_type, resource_id) = resource.split("/")
        else:
            resource_type, resource_id = None, resource
    elif len(resource) == 2:
        (resource_type, resource_id) = resource_id
    else:
        raise InvalidARNError(arn)

    return ARN(
        partition or None,
        service or None,
        region or None,
        account_id or None,
        resource_type or None,
        resource_id or None,
    )
