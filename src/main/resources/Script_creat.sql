create table oauth_access_token
(
    token_id          varchar(256) not null
        primary key,
    token             bytea,
    authentication_id varchar(256) not null,
    user_name         varchar(256),
    client_id         varchar(256),
    authentication    bytea,
    refresh_token     varchar(256)
);

alter table oauth_access_token
    owner to postgres;

create index oauth_access_token_authentication_id_index
    on oauth_access_token (authentication_id);

create table oauth_approvals
(
    userid         varchar(256),
    clientid       varchar(256),
    scope          varchar(256),
    status         varchar(10),
    expiresat      timestamp,
    lastmodifiedat timestamp
);

alter table oauth_approvals
    owner to postgres;

create table oauth_client_details
(
    client_id               varchar(256) not null
        primary key,
    resource_ids            varchar(256),
    client_secret           varchar(256),
    scope                   varchar(256),
    authorized_grant_types  varchar(256),
    web_server_redirect_uri varchar(256),
    authorities             varchar(256),
    access_token_validity   integer,
    refresh_token_validity  integer,
    additional_information  varchar(4096),
    autoapprove             varchar(256)
);

alter table oauth_client_details
    owner to postgres;

create table oauth_client_token
(
    token_id          varchar(256),
    token             bytea,
    authentication_id varchar(256) not null
        primary key,
    user_name         varchar(256),
    client_id         varchar(256)
);

alter table oauth_client_token
    owner to postgres;

create table oauth_code
(
    code           varchar(256),
    authentication bytea
);

alter table oauth_code
    owner to postgres;

create table oauth_refresh_token
(
    token_id       varchar(256),
    token          bytea,
    authentication bytea
);

alter table oauth_refresh_token
    owner to postgres;



INSERT INTO public.oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types,
                                         web_server_redirect_uri, authorities, access_token_validity,
                                         refresh_token_validity, additional_information, autoapprove)
VALUES ('OAUTH', 'OAUTH,AUTH', '$2a$04$9timSiqpo3EMgNm0Hh6oYe3GvxOVSOPEoizCsvRlQYlgj2.s/ee5C', 'read,write,trust',
        'password,authorization_code,refresh_token,implicit', null, null, 864000000, null, null, 'true');
