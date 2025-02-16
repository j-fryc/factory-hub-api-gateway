from enum import Enum


class ApplicationRoles(Enum):
    APPLICATION_ADMIN = 'application_admin'
    APPLICATION_USER = 'application_user'


class OrganisationRoles(Enum):
    ORGANISATION_ADMIN = 'organisation_admin'
    ORGANISATION_MANAGER = 'organisation_manager'
    ORGANISATION_USER = 'organisation_user'
