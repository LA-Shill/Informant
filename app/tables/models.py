# !/usr/bin/env python
# Name:     models.py
# By:       LA-Shill
# Date:     24.02.2021
# Version   0.3
# -----------------------------------------------

# Import libraries
from .serverside_table import ServerSideTable
import datetime as dt

# Table Schemas
PDNS_TABLE_COLUMNS = [
    {
        "data_name": "timestamp",
        "column_name": "timestamp",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "ip",
        "column_name": "Source",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "asn",
        "column_name": "ASN",
        "default": "",
        "order": 2,
        "searchable": True
    },
    {
        "data_name": "netname",
        "column_name": "Netname",
        "default": "",
        "order": 3,
        "searchable": True
    },
    {
        "data_name": "domain",
        "column_name": "Destination",
        "default": "",
        "order": 4,
        "searchable": True
    },
    {
        "data_name": "first_seen",
        "column_name": "first_seen",
        "default": "",
        "order": 5,
        "searchable": True
    },
    {
        "data_name": "last_seen",
        "column_name": "last_seen",
        "default": "",
        "order": 6,
        "searchable": True
    },
    {
        "data_name": "count",
        "column_name": "Count",
        "default": 0,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "flagged",
        "column_name": "flagged",
        "default": False,
        "order": 7,
        "searchable": True
    }
]


PDNS_1_TABLE_COLUMNS = [
    {
        "data_name": "timestamp",
        "column_name": "timestamp",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "ip",
        "column_name": "Source",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "asn",
        "column_name": "ASN",
        "default": "",
        "order": 2,
        "searchable": True
    },
    {
        "data_name": "netname",
        "column_name": "Netname",
        "default": "",
        "order": 3,
        "searchable": True
    },
    {
        "data_name": "domain",
        "column_name": "Destination",
        "default": "",
        "order": 4,
        "searchable": True
    },
    {
        "data_name": "first_seen",
        "column_name": "first_seen",
        "default": "",
        "order": 5,
        "searchable": True
    },
    {
        "data_name": "last_seen",
        "column_name": "last_seen",
        "default": "",
        "order": 6,
        "searchable": True
    },
    {
        "data_name": "count",
        "column_name": "Count",
        "default": 0,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "flagged",
        "column_name": "flagged",
        "default": False,
        "order": 7,
        "searchable": True
    }
]


IWS_TABLE_COLUMNS = [
    {
        "data_name": "timestamp",
        "column_name": "timestamp",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "ip",
        "column_name": "IP",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "asn",
        "column_name": "ASN",
        "default": "",
        "order": 2,
        "searchable": True
    },
    {
        "data_name": "domains",
        "column_name": "Domains",
        "default": "",
        "order": 3,
        "searchable": True
    },
    {
        "data_name": "hostnames",
        "column_name": "Hostnames",
        "default": "",
        "order": 4,
        "searchable": True
    },
    {
        "data_name": "org",
        "column_name": "Organisation",
        "default": "",
        "order": 5,
        "searchable": True
    },
    {
        "data_name": "country",
        "column_name": "Country",
        "default": "",
        "order": 6,
        "searchable": True
    },
    {
        "data_name": "os",
        "column_name": "OS",
        "default": 0,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "ports",
        "column_name": "Ports",
        "default": False,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "cveData",
        "column_name": "Services",
        "default": False,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "risks",
        "column_name": "Flags",
        "default": False,
        "order": 7,
        "searchable": True
    }
]


IWS_1_TABLE_COLUMNS = [
    {
        "data_name": "ip",
        "column_name": "IP",
        "default": "",
        "order": 1,
        "searchable": True
    },
    {
        "data_name": "asn",
        "column_name": "ASN",
        "default": "",
        "order": 2,
        "searchable": True
    },
    {
        "data_name": "domains",
        "column_name": "Domains",
        "default": "",
        "order": 3,
        "searchable": True
    },
    {
        "data_name": "hostnames",
        "column_name": "Hostnames",
        "default": "",
        "order": 4,
        "searchable": True
    },
    {
        "data_name": "org",
        "column_name": "Organisation",
        "default": "",
        "order": 5,
        "searchable": True
    },
    {
        "data_name": "country",
        "column_name": "Country",
        "default": "",
        "order": 6,
        "searchable": True
    },
    {
        "data_name": "os",
        "column_name": "OS",
        "default": 0,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "ports",
        "column_name": "Ports",
        "default": False,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "banners",
        "column_name": "Services",
        "default": False,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "risks",
        "column_name": "Flags",
        "default": False,
        "order": 7,
        "searchable": True
    },
    {
        "data_name": "timestamp",
        "column_name": "Timestamp",
        "default": "",
        "order": 7,
        "searchable": True
    }
]


class TableBuilder(object):
    """
        Serverside Ajax datatable handling
        and clientside handler
    """
    def collect_data_clientside(self, data):
        return {'data': data}

    def collect_data_serverside(self, request, data, schema):

        # Select DT schema
        if schema == 'PDNS_0':
            columns = PDNS_TABLE_COLUMNS
        elif schema == 'PDNS_1':
            columns = PDNS_1_TABLE_COLUMNS
        elif schema == 'IWS_0':
            columns = IWS_TABLE_COLUMNS
        elif schema == 'IWS_1':
            columns = IWS_1_TABLE_COLUMNS

        # Perform serverside DT operations
        ServerSideTable(request, data, columns).output_result()

        # Return data to frontend
        return ServerSideTable(request, data, columns).output_result()