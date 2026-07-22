"""Legacy Indy Registry."""

import json
import logging
import re
from asyncio import Lock, shield, to_thread
from typing import List, Optional, Pattern, Sequence, Tuple

from base58 import alphabet
from web3 import Web3
from web3.exceptions import ContractCustomError
from web3.middleware import geth_poa_middleware
from web3.types import TxReceipt

from ....anoncreds.events import RevListFinishedEvent
from ....cache.base import BaseCache
from ....config.injection_context import InjectionContext
from ....core.event_bus import EventBus
from ....core.profile import Profile
from ....ledger.base import BaseLedger
from ....ledger.error import (
    LedgerError,
    LedgerObjectAlreadyExistsError,
    LedgerTransactionError,
)
from ....ledger.merkel_validation.constants import GET_SCHEMA
from ....ledger.multiple_ledger.ledger_requests_executor import (
    GET_CRED_DEF,
    IndyLedgerRequestsExecutor,
)
from ....multitenant.base import BaseMultitenantManager
from ....revocation_anoncreds.models.issuer_cred_rev_record import IssuerCredRevRecord
from ....revocation_anoncreds.recover import generate_ledger_rrrecovery_txn
from ...base import (
    AnonCredsObjectAlreadyExists,
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    AnonCredsSchemaAlreadyExists,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from ...issuer import AnonCredsIssuer, AnonCredsIssuerError
from ...models.anoncreds_cred_def import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from ...models.anoncreds_revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevRegDefValue,
)
from ...models.anoncreds_schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_SIGNATURE_TYPE = "CL"

ROLE_CONTROL_ABI = ""
VALIDATOR_CONTROL_ABI = ""
CRED_DEF_REGISTRY_ABI = '[    {     "inputs": [      {       "internalType": "address",       "name": "target",       "type": "address"      }     ],     "name": "AddressEmptyCode",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "CredentialDefinitionAlreadyExist",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "CredentialDefinitionNotFound",     "type": "error"    },    {     "inputs": [      {       "internalType": "address",       "name": "implementation",       "type": "address"      }     ],     "name": "ERC1967InvalidImplementation",     "type": "error"    },    {     "inputs": [],     "name": "ERC1967NonPayable",     "type": "error"    },    {     "inputs": [],     "name": "FailedInnerCall",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "name",       "type": "string"      }     ],     "name": "FieldRequired",     "type": "error"    },    {     "inputs": [],     "name": "InvalidInitialization",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "InvalidIssuerId",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "IssuerHasBeenDeactivated",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "IssuerNotFound",     "type": "error"    },    {     "inputs": [],     "name": "NotInitializing",     "type": "error"    },    {     "inputs": [],     "name": "PackedPtrLen__LenOverflow",     "type": "error"    },    {     "inputs": [],     "name": "PackedPtrLen__PtrOverflow",     "type": "error"    },    {     "inputs": [      {       "internalType": "address",       "name": "sender",       "type": "address"      },      {       "internalType": "address",       "name": "owner",       "type": "address"      }     ],     "name": "SenderIsNotIssuerDidOwner",     "type": "error"    },    {     "inputs": [],     "name": "UUPSUnauthorizedCallContext",     "type": "error"    },    {     "inputs": [      {       "internalType": "bytes32",       "name": "slot",       "type": "bytes32"      }     ],     "name": "UUPSUnsupportedProxiableUUID",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "credDefType",       "type": "string"      }     ],     "name": "UnsupportedCredentialDefinitionType",     "type": "error"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "string",       "name": "credentialDefinitionId",       "type": "string"      },      {       "indexed": true,       "internalType": "address",       "name": "sender",       "type": "address"      }     ],     "name": "CredentialDefinitionCreated",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "uint64",       "name": "version",       "type": "uint64"      }     ],     "name": "Initialized",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": true,       "internalType": "address",       "name": "implementation",       "type": "address"      }     ],     "name": "Upgraded",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "string",       "name": "reason",       "type": "string"      }     ],     "name": "testError",     "type": "event"    },    {     "inputs": [],     "name": "UPGRADE_INTERFACE_VERSION",     "outputs": [      {       "internalType": "string",       "name": "",       "type": "string"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "components": [        {         "internalType": "string",         "name": "id",         "type": "string"        },        {         "internalType": "string",         "name": "issuerId",         "type": "string"        },        {         "internalType": "string",         "name": "schemaId",         "type": "string"        },        {         "internalType": "string",         "name": "credDefType",         "type": "string"        },        {         "internalType": "string",         "name": "tag",         "type": "string"        },        {         "internalType": "string",         "name": "value",         "type": "string"        }       ],       "internalType": "struct CredentialDefinition",       "name": "credDef",       "type": "tuple"      }     ],     "name": "createCredentialDefinition",     "outputs": [],     "stateMutability": "nonpayable",     "type": "function"    },    {     "inputs": [      {       "internalType": "address",       "name": "upgradeControlAddress",       "type": "address"      },      {       "internalType": "address",       "name": "didResolverAddress",       "type": "address"      },      {       "internalType": "address",       "name": "schemaRegistryAddress",       "type": "address"      }     ],     "name": "initialize",     "outputs": [],     "stateMutability": "nonpayable",     "type": "function"    },    {     "inputs": [],     "name": "proxiableUUID",     "outputs": [      {       "internalType": "bytes32",       "name": "",       "type": "bytes32"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "resolveCredentialDefinition",     "outputs": [      {       "components": [        {         "components": [          {           "internalType": "string",           "name": "id",           "type": "string"          },          {           "internalType": "string",           "name": "issuerId",           "type": "string"          },          {           "internalType": "string",           "name": "schemaId",           "type": "string"          },          {           "internalType": "string",           "name": "credDefType",           "type": "string"          },          {           "internalType": "string",           "name": "tag",           "type": "string"          },          {           "internalType": "string",           "name": "value",           "type": "string"          }         ],         "internalType": "struct CredentialDefinition",         "name": "credDef",         "type": "tuple"        },        {         "components": [          {           "internalType": "uint256",           "name": "created",           "type": "uint256"          }         ],         "internalType": "struct CredentialDefinitionMetadata",         "name": "metadata",         "type": "tuple"        }       ],       "internalType": "struct CredentialDefinitionWithMetadata",       "name": "credDefWithMetadata",       "type": "tuple"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "internalType": "address",       "name": "newImplementation",       "type": "address"      },      {       "internalType": "bytes",       "name": "data",       "type": "bytes"      }     ],     "name": "upgradeToAndCall",     "outputs": [],     "stateMutability": "payable",     "type": "function"    }   ]'
SCHEMA_REGISTRY_ABI = '[    {     "inputs": [      {       "internalType": "address",       "name": "target",       "type": "address"      }     ],     "name": "AddressEmptyCode",     "type": "error"    },    {     "inputs": [      {       "internalType": "address",       "name": "implementation",       "type": "address"      }     ],     "name": "ERC1967InvalidImplementation",     "type": "error"    },    {     "inputs": [],     "name": "ERC1967NonPayable",     "type": "error"    },    {     "inputs": [],     "name": "FailedInnerCall",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "name",       "type": "string"      }     ],     "name": "FieldRequired",     "type": "error"    },    {     "inputs": [],     "name": "InvalidInitialization",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "InvalidIssuerId",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "InvalidSchemaId",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "IssuerHasBeenDeactivated",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "IssuerNotFound",     "type": "error"    },    {     "inputs": [],     "name": "NotInitializing",     "type": "error"    },    {     "inputs": [],     "name": "PackedPtrLen__LenOverflow",     "type": "error"    },    {     "inputs": [],     "name": "PackedPtrLen__PtrOverflow",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "SchemaAlreadyExist",     "type": "error"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "SchemaNotFound",     "type": "error"    },    {     "inputs": [      {       "internalType": "address",       "name": "sender",       "type": "address"      },      {       "internalType": "address",       "name": "owner",       "type": "address"      }     ],     "name": "SenderIsNotIssuerDidOwner",     "type": "error"    },    {     "inputs": [],     "name": "UUPSUnauthorizedCallContext",     "type": "error"    },    {     "inputs": [      {       "internalType": "bytes32",       "name": "slot",       "type": "bytes32"      }     ],     "name": "UUPSUnsupportedProxiableUUID",     "type": "error"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "uint64",       "name": "version",       "type": "uint64"      }     ],     "name": "Initialized",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "string",       "name": "schemaId",       "type": "string"      },      {       "indexed": true,       "internalType": "address",       "name": "sender",       "type": "address"      }     ],     "name": "SchemaCreated",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": true,       "internalType": "address",       "name": "implementation",       "type": "address"      }     ],     "name": "Upgraded",     "type": "event"    },    {     "anonymous": false,     "inputs": [      {       "indexed": false,       "internalType": "string",       "name": "reason",       "type": "string"      }     ],     "name": "testError",     "type": "event"    },    {     "inputs": [],     "name": "UPGRADE_INTERFACE_VERSION",     "outputs": [      {       "internalType": "string",       "name": "",       "type": "string"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "components": [        {         "internalType": "string",         "name": "id",         "type": "string"        },        {         "internalType": "string",         "name": "issuerId",         "type": "string"        },        {         "internalType": "string",         "name": "name",         "type": "string"        },        {         "internalType": "string",         "name": "version",         "type": "string"        },        {         "internalType": "string[]",         "name": "attrNames",         "type": "string[]"        }       ],       "internalType": "struct Schema",       "name": "schema",       "type": "tuple"      }     ],     "name": "createSchema",     "outputs": [],     "stateMutability": "nonpayable",     "type": "function"    },    {     "inputs": [      {       "internalType": "address",       "name": "upgradeControlAddress",       "type": "address"      },      {       "internalType": "address",       "name": "didResolverAddress",       "type": "address"      }     ],     "name": "initialize",     "outputs": [],     "stateMutability": "nonpayable",     "type": "function"    },    {     "inputs": [],     "name": "proxiableUUID",     "outputs": [      {       "internalType": "bytes32",       "name": "",       "type": "bytes32"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "internalType": "string",       "name": "id",       "type": "string"      }     ],     "name": "resolveSchema",     "outputs": [      {       "components": [        {         "components": [          {           "internalType": "string",           "name": "id",           "type": "string"          },          {           "internalType": "string",           "name": "issuerId",           "type": "string"          },          {           "internalType": "string",           "name": "name",           "type": "string"          },          {           "internalType": "string",           "name": "version",           "type": "string"          },          {           "internalType": "string[]",           "name": "attrNames",           "type": "string[]"          }         ],         "internalType": "struct Schema",         "name": "schema",         "type": "tuple"        },        {         "components": [          {           "internalType": "uint256",           "name": "created",           "type": "uint256"          }         ],         "internalType": "struct SchemaMetadata",         "name": "metadata",         "type": "tuple"        }       ],       "internalType": "struct SchemaWithMetadata",       "name": "schemaWithMetadata",       "type": "tuple"      }     ],     "stateMutability": "view",     "type": "function"    },    {     "inputs": [      {       "internalType": "address",       "name": "newImplementation",       "type": "address"      },      {       "internalType": "bytes",       "name": "data",       "type": "bytes"      }     ],     "name": "upgradeToAndCall",     "outputs": [],     "stateMutability": "payable",     "type": "function"    }   ]'
DID_REGISTRY_ABI = ""
REVOCATION_REGISTRY_ABI = '[  {   "inputs": [    {     "internalType": "address",     "name": "target",     "type": "address"    }   ],   "name": "AddressEmptyCode",   "type": "error"  },  {   "inputs": [    {     "internalType": "address",     "name": "implementation",     "type": "address"    }   ],   "name": "ERC1967InvalidImplementation",   "type": "error"  },  {   "inputs": [],   "name": "ERC1967NonPayable",   "type": "error"  },  {   "inputs": [],   "name": "FailedInnerCall",   "type": "error"  },  {   "inputs": [],   "name": "InvalidInitialization",   "type": "error"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "InvalidIssuerId",   "type": "error"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "IssuerHasBeenDeactivated",   "type": "error"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "IssuerNotFound",   "type": "error"  },  {   "inputs": [],   "name": "NotInitializing",   "type": "error"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "RevocationAlreadyExist",   "type": "error"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "RevocationNotFound",   "type": "error"  },  {   "inputs": [    {     "internalType": "address",     "name": "sender",     "type": "address"    },    {     "internalType": "address",     "name": "creator",     "type": "address"    }   ],   "name": "SenderIsNotCreator",   "type": "error"  },  {   "inputs": [    {     "internalType": "address",     "name": "sender",     "type": "address"    },    {     "internalType": "address",     "name": "owner",     "type": "address"    }   ],   "name": "SenderIsNotIssuerDidOwner",   "type": "error"  },  {   "inputs": [],   "name": "UUPSUnauthorizedCallContext",   "type": "error"  },  {   "inputs": [    {     "internalType": "bytes32",     "name": "slot",     "type": "bytes32"    }   ],   "name": "UUPSUnsupportedProxiableUUID",   "type": "error"  },  {   "anonymous": false,   "inputs": [    {     "indexed": false,     "internalType": "string",     "name": "RevocationId",     "type": "string"    },    {     "indexed": true,     "internalType": "address",     "name": "sender",     "type": "address"    }   ],   "name": "CredentialRevoked",   "type": "event"  },  {   "anonymous": false,   "inputs": [    {     "indexed": false,     "internalType": "string",     "name": "RevocationId",     "type": "string"    },    {     "indexed": true,     "internalType": "address",     "name": "sender",     "type": "address"    }   ],   "name": "CredentialUnrevoked",   "type": "event"  },  {   "anonymous": false,   "inputs": [    {     "indexed": false,     "internalType": "uint64",     "name": "version",     "type": "uint64"    }   ],   "name": "Initialized",   "type": "event"  },  {   "anonymous": false,   "inputs": [    {     "indexed": false,     "internalType": "string",     "name": "RevRegId",     "type": "string"    },    {     "indexed": true,     "internalType": "address",     "name": "sender",     "type": "address"    }   ],   "name": "RevListCreated",   "type": "event"  },  {   "anonymous": false,   "inputs": [    {     "indexed": false,     "internalType": "string",     "name": "RevocationId",     "type": "string"    },    {     "indexed": true,     "internalType": "address",     "name": "sender",     "type": "address"    }   ],   "name": "RevocationCreated",   "type": "event"  },  {   "anonymous": false,   "inputs": [    {     "indexed": true,     "internalType": "address",     "name": "implementation",     "type": "address"    }   ],   "name": "Upgraded",   "type": "event"  },  {   "inputs": [],   "name": "UPGRADE_INTERFACE_VERSION",   "outputs": [    {     "internalType": "string",     "name": "",     "type": "string"    }   ],   "stateMutability": "view",   "type": "function"  },  {   "inputs": [    {     "components": [      {       "internalType": "string",       "name": "revDefId",       "type": "string"      },      {       "internalType": "string",       "name": "regDefType",       "type": "string"      },      {       "internalType": "string",       "name": "entry",       "type": "string"      },      {       "internalType": "string",       "name": "issuerId",       "type": "string"      }     ],     "internalType": "struct RevocationRegEntry",     "name": "revEntry",     "type": "tuple"    }   ],   "name": "createOrUpdateEntry",   "outputs": [],   "stateMutability": "nonpayable",   "type": "function"  },  {   "inputs": [    {     "components": [      {       "internalType": "string",       "name": "id",       "type": "string"      },      {       "internalType": "string",       "name": "issuerId",       "type": "string"      },      {       "internalType": "string",       "name": "credDefId",       "type": "string"      }     ],     "internalType": "struct Revocation",     "name": "_revocation",     "type": "tuple"    }   ],   "name": "createRevocation",   "outputs": [],   "stateMutability": "nonpayable",   "type": "function"  },  {   "inputs": [    {     "components": [      {       "internalType": "string",       "name": "ver",       "type": "string"      },      {       "internalType": "string",       "name": "id",       "type": "string"      },      {       "internalType": "string",       "name": "revocDefType",       "type": "string"      },      {       "internalType": "string",       "name": "credDefId",       "type": "string"      },      {       "internalType": "string",       "name": "tag",       "type": "string"      },      {       "internalType": "string",       "name": "value",       "type": "string"      },      {       "internalType": "string",       "name": "issuerId",       "type": "string"      }     ],     "internalType": "struct RevocationReg",     "name": "revRegistry",     "type": "tuple"    }   ],   "name": "createRevocationRegistry",   "outputs": [],   "stateMutability": "nonpayable",   "type": "function"  },  {   "inputs": [    {     "internalType": "address",     "name": "upgradeControlAddress",     "type": "address"    },    {     "internalType": "address",     "name": "didResolverAddress",     "type": "address"    },    {     "internalType": "address",     "name": "credDefRegistryAddress",     "type": "address"    }   ],   "name": "initialize",   "outputs": [],   "stateMutability": "nonpayable",   "type": "function"  },  {   "inputs": [],   "name": "proxiableUUID",   "outputs": [    {     "internalType": "bytes32",     "name": "",     "type": "bytes32"    }   ],   "stateMutability": "view",   "type": "function"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "resolveEntry",   "outputs": [    {     "components": [      {       "components": [        {         "internalType": "string",         "name": "revDefId",         "type": "string"        },        {         "internalType": "string",         "name": "regDefType",         "type": "string"        },        {         "internalType": "string",         "name": "entry",         "type": "string"        },        {         "internalType": "string",         "name": "issuerId",         "type": "string"        }       ],       "internalType": "struct RevocationRegEntry",       "name": "revEntry",       "type": "tuple"      },      {       "components": [        {         "internalType": "uint256",         "name": "created",         "type": "uint256"        },        {         "internalType": "address",         "name": "creator",         "type": "address"        },        {         "internalType": "uint256",         "name": "updated",         "type": "uint256"        }       ],       "internalType": "struct RevocationEntryMetadata",       "name": "metadata",       "type": "tuple"      }     ],     "internalType": "struct RevocationEntryWithMetadata",     "name": "revEntryMetadata",     "type": "tuple"    }   ],   "stateMutability": "view",   "type": "function"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "resolveRevocation",   "outputs": [    {     "components": [      {       "components": [        {         "internalType": "string",         "name": "ver",         "type": "string"        },        {         "internalType": "string",         "name": "id",         "type": "string"        },        {         "internalType": "string",         "name": "revocDefType",         "type": "string"        },        {         "internalType": "string",         "name": "credDefId",         "type": "string"        },        {         "internalType": "string",         "name": "tag",         "type": "string"        },        {         "internalType": "string",         "name": "value",         "type": "string"        },        {         "internalType": "string",         "name": "issuerId",         "type": "string"        }       ],       "internalType": "struct RevocationReg",       "name": "revocationReg",       "type": "tuple"      },      {       "components": [        {         "internalType": "uint256",         "name": "created",         "type": "uint256"        },        {         "internalType": "address",         "name": "creator",         "type": "address"        },        {         "internalType": "uint256",         "name": "updated",         "type": "uint256"        }       ],       "internalType": "struct RevocationRegMetadata",       "name": "metadata",       "type": "tuple"      }     ],     "internalType": "struct RevocationRegWithMetadata",     "name": "revWithMetadata",     "type": "tuple"    }   ],   "stateMutability": "view",   "type": "function"  },  {   "inputs": [    {     "internalType": "string",     "name": "id",     "type": "string"    }   ],   "name": "revokeCredential",   "outputs": [],   "stateMutability": "nonpayable",   "type": "function"  },  {   "inputs": [    {     "internalType": "address",     "name": "newImplementation",     "type": "address"    },    {     "internalType": "bytes",     "name": "data",     "type": "bytes"    }   ],   "name": "upgradeToAndCall",   "outputs": [],   "stateMutability": "payable",   "type": "function"  } ]'


class DIDBesuRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDBesuRegistry."""

    def __init__(self):
        """Initialize an instance.

        Args:
        TODO: update this docstring - Anoncreds-break.

        """
        B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")
        INDY_DID = rf"^(did:indy2)?:.+:[{B58}]{{21,22}}$"
        INDY_SCHEMA_ID = (
            rf"^(did:indy2)?:.+:[{B58}]{{21,22}}/anoncreds/v0/SCHEMA/.+/[0-9.]+$"
        )
        # schema
        # ["did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97/anoncreds/v0/SCHEMA/BasicIdentity/1.0.0","did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97", "BasicIdentity","1.0.0", ["First Name","Last Name"]]
        # credef
        # ["did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97/anoncreds/v0/CLAIM_DEF/did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97/anoncreds/v0/SCHEMA/BasicIdentity/1.0.0/BasicIdentity","did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97", "did:indy2:testnet:WedHLJdFf4yMaDXdhJcL97/anoncreds/v0/SCHEMA/BasicIdentity/1.0.0", "CL", "BasicIdentity", "<keys>"]
        INDY_CRED_DEF_ID = (
            rf"^((did:indy2)?:.+:[{B58}]{{21,22}})"  # issuer DID
            f"/anoncreds/v0/CLAIM_DEF/"  # cred def id marker
            # f":CL"  # sig alg
            rf"((did:indy2)?:.+:[{B58}]{{21,22}}/anoncreds/v0/SCHEMA/.+/[0-9.]+)"  # schema txn / id
            f"/(.+)?$"  # tag
        )
        INDY_REV_REG_DEF_ID = (
            rf"^((did:indy2)?:.+:[{B58}]{{21,22}})"  # issuer DID
            f"/anoncreds/v0/REV_REG/"  # cred def id marker
            rf"((did:indy2)?:.+:[{B58}]{{21,22}})"  # issuer DID
            f"/anoncreds/v0/CLAIM_DEF/"  # cred def id marker
            # f":CL"  # sig alg
            rf"((did:indy2)?:.+:[{B58}]{{21,22}}/anoncreds/v0/SCHEMA/.+/[0-9.]+)"  # schema txn / id
            f"/(.+)?$"  # tag
        )
        self._supported_identifiers_regex = re.compile(
            rf"{INDY_DID}|{INDY_SCHEMA_ID}|{INDY_CRED_DEF_ID}|{INDY_REV_REG_DEF_ID}"
        )
        self.web3 = None
        # default values
        self.HTTP_PROVIDER = None
        self.ACCOUNT = None
        self.PKEY = None
        self.SCHEMA_REGISTRY_ADDRESS = None
        self.CRED_DEF_REGISTRY_ADDRESS = None
        self.VALIDATOR_CONTROL_ADDRESS = None
        self.ROLE_CONTROL_ADDRESS = None
        self.REVOCATION_ADDRESS = None
        self.REVOCATION_LIST_GAS_LIMIT = 3000000
        # Serializes nonce-fetch-through-submit for this replica. get_transaction_count
        # reflects only *confirmed* transactions, so two concurrent writers on this
        # same account could otherwise fetch the same nonce before either transaction
        # is mined. Held from the nonce fetch through send_transaction_tx returning
        # (i.e. through confirmation) in register_revocation,
        # register_revocation_registry_definition, and _revoc_reg_entry_with_fix --
        # not around anything else, so unrelated credential issuance/verification
        # (which never touch the ledger) and reads (the resolve*().call() checks)
        # are unaffected.
        self._tx_lock = Lock()

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers Regular Expression."""
        return self._supported_identifiers_regex

    async def setup(self, context: InjectionContext):
        """Setup."""
        self.ACCOUNT = context.settings.get("ledger.account_address")
        self.PKEY = context.settings.get("ledger.private_account_key")
        self.HTTP_PROVIDER = context.settings.get("ledger.besu_provider_url")
        self.SCHEMA_REGISTRY_ADDRESS = context.settings.get(
            "ledger.schema_contract_address"
        )
        self.CRED_DEF_REGISTRY_ADDRESS = context.settings.get(
            "ledger.credef_contract_address"
        )
        self.REVOCATION_ADDRESS = context.settings.get(
            "ledger.revocation_contract_address"
        )
        if context.settings.get("ledger.revocation_list_gas_limit"):
            self.REVOCATION_LIST_GAS_LIMIT = context.settings.get(
                "ledger.revocation_list_gas_limit"
            )

        self.web3 = Web3(Web3.HTTPProvider(self.HTTP_PROVIDER))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        print("Successfully registered DIDBesuRegistry")

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema) -> str:
        """Derive the ID for a schema."""
        # https://hyperledger.github.io/indy-did-method/#schema
        return f"{schema.issuer_id}/anoncreds/v0/SCHEMA/{schema.name}/{schema.version}"

    @staticmethod
    def make_cred_def_id(
        schema: GetSchemaResult,
        cred_def: CredDef,
    ) -> str:
        """Derive the ID for a credential definition."""
        # https://hyperledger.github.io/indy-did-method/#cred-def
        tag = cred_def.tag or DEFAULT_CRED_DEF_TAG
        return f"{cred_def.issuer_id}/anoncreds/v0/CLAIM_DEF/{schema.schema_id}/{tag}"

    @staticmethod
    def make_rev_reg_def_id(rev_reg_def: RevRegDef) -> str:
        """Derive the ID for a revocation registry definition."""
        # https://hyperledger.github.io/indy-did-method/#revocation-registry-definition
        return (
            f"{rev_reg_def.issuer_id}/anoncreds/v0/REV_REG_DEF/{rev_reg_def.cred_def_id}:"
            f"{rev_reg_def.type}:{rev_reg_def.tag}"
        )

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""

        multitenant_mgr = profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
        else:
            ledger_exec_inst = profile.inject(IndyLedgerRequestsExecutor)
        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            schema_id,
            txn_record_type=GET_SCHEMA,
        )

        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsResolutionError(reason)

        async with ledger:
            try:
                schema = await ledger.get_schema(schema_id)
                if schema is None:
                    raise AnonCredsObjectNotFound(
                        f"Schema not found: {schema_id}",
                        {"ledger_id": ledger_id},
                    )

                anoncreds_schema = AnonCredsSchema(
                    issuer_id=schema["issuerId"],
                    attr_names=schema["attrNames"],
                    name=schema["name"],
                    version=schema["version"],
                )
                result = GetSchemaResult(
                    schema=anoncreds_schema,
                    schema_id=schema["id"],
                    resolution_metadata={"ledger_id": ledger_id},
                    schema_metadata={"seqNo": schema["seqNo"]},
                )
            except LedgerError as err:
                raise AnonCredsResolutionError("Failed to retrieve schema") from err

        return result

    def _send_transaction_tx_sync(self, call_function) -> TxReceipt:
        """Synchronous body of send_transaction_tx.

        Runs off the event loop (see send_transaction_tx below) since
        web3.eth.wait_for_transaction_receipt polls synchronously for up to
        120s (web3.py default, no timeout configured here) waiting for the
        besu transaction to be mined -- without offloading this, that wait
        blocks the entire ACA-Py process on this replica, not just the
        caller, for the whole duration.
        """
        # Sign transaction
        signed_tx = self.web3.eth.account.sign_transaction(
            call_function, private_key=self.PKEY
        )

        # Send transaction
        # LOGGER.debug("Transaction: %s", signed_tx.rawTransaction)
        send_tx = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)

        # Wait for transaction receipt
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(
            transaction_hash=send_tx, poll_latency=1.0
        )

        if tx_receipt["status"] == 0:
            LOGGER.debug("Receipt of the reverted transaction: %s", tx_receipt)
            raise AnonCredsRegistrationError("Transaction reverted: %s", send_tx)

        return tx_receipt

    async def send_transaction_tx(self, call_function) -> TxReceipt:
        """DEPRECATED."""
        # FIXME: remove me
        return await to_thread(self._send_transaction_tx_sync, call_function)

    async def register_revocation(
        self, revocation_id: str, issuer_id: str, credDef_id: str
    ) -> TxReceipt:
        """Register a revocation on the registry. (BETA)."""
        LOGGER.debug(f"Registering revocation: {revocation_id}")
        rev_json = {"id": revocation_id, "issuerId": issuer_id, "credDefId": credDef_id}
        abi = json.loads(REVOCATION_REGISTRY_ABI)
        address = self.web3.to_checksum_address(self.REVOCATION_ADDRESS)
        contract = self.web3.eth.contract(address=address, abi=abi)
        Chain_id = self.web3.eth.chain_id
        call_function = contract.functions.createRevocation(rev_json)

        try:
            estimated_gas = call_function.estimate_gas({"from": self.ACCOUNT})
            gas_limit = int(estimated_gas * 1.2)  # 20% safety margin
        except Exception as e:
            LOGGER.warning("Failed to estimate gas: %s. Using fallback from config.", e)
            gas_limit = int(self.REVOCATION_LIST_GAS_LIMIT)

        async with self._tx_lock:
            nonce = self.web3.eth.get_transaction_count(self.ACCOUNT)
            tx = call_function.build_transaction(
                {
                    "chainId": Chain_id,
                    "from": self.ACCOUNT,
                    "nonce": nonce,
                    "gas": gas_limit,
                    "gasPrice": self.web3.eth.gas_price,
                }
            )

            LOGGER.debug("Sending contract function %s: tuple %s", call_function.fn_name, call_function.arguments)
            tx_receipt = await self.send_transaction_tx(tx)

        # receipt = contract.functions.createSchema(indy_schema).transact({"from": self.ACCOUNT})
        LOGGER.debug("Receipt: %s", tx_receipt)
        # Was it realy created?
        result = contract.functions.resolveRevocation(revocation_id).call()

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""

        schema_id = self.make_schema_id(schema)

        # Assume endorser role on the network, no option for 3rd-party endorser
        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            raise AnonCredsRegistrationError("No ledger available")

        # Translate schema into format expected by Indy
        LOGGER.debug("Registering schema: %s", schema_id)
        indy_schema = {
            "id": schema_id,
            "issuerId": schema.issuer_id,
            "name": schema.name,
            "version": schema.version,
            "attrNames": schema.attr_names,
            # "seqNo": None,
        }

        async with ledger:
            try:
                await shield(
                    ledger.send_schema_anoncreds(
                        schema_id,
                        indy_schema,
                        write_ledger=True,
                        endorser_did=None,
                    )
                )
            except LedgerObjectAlreadyExistsError as err:
                raise AnonCredsSchemaAlreadyExists(err.message, err.obj_id, schema)
            except (AnonCredsIssuerError, LedgerError) as err:
                raise AnonCredsRegistrationError("Failed to register schema") from err

        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={},
            schema_metadata={"tx_hash": None},  # "seqNo": seq_no},
        )

    async def get_credential_definition(
        self, profile: Profile, cred_def_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""

        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            cred_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsResolutionError(reason)

        async with ledger:
            cred_def = await ledger.get_credential_definition(cred_def_id)

            if cred_def is None:
                raise AnonCredsObjectNotFound(
                    f"Credential definition not found: {cred_def_id}",
                    {"ledger_id": ledger_id},
                )

            cred_def_value = CredDefValue.deserialize(cred_def["value"])
            anoncreds_credential_definition = CredDef(
                issuer_id=cred_def["issuerId"],
                schema_id=cred_def["schemaId"],
                type=cred_def["type"],
                tag=cred_def["tag"],
                value=cred_def_value,
            )
            anoncreds_registry_get_credential_definition = GetCredDefResult(
                credential_definition=anoncreds_credential_definition,
                credential_definition_id=cred_def["id"],
                resolution_metadata={},
                credential_definition_metadata={},
            )
        return anoncreds_registry_get_credential_definition

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""

        cred_def_id = self.make_cred_def_id(schema, credential_definition)

        ledger = profile.inject_or(BaseLedger)
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsRegistrationError(reason)

        # Check if in wallet but not on ledger
        issuer = AnonCredsIssuer(profile)
        if await issuer.credential_definition_in_wallet(cred_def_id):
            try:
                await self.get_credential_definition(profile, cred_def_id)
            except AnonCredsObjectNotFound as err:
                raise AnonCredsRegistrationError(
                    f"Credential definition with id {cred_def_id} already "
                    "exists in wallet but not on the ledger"
                ) from err

        # Translate anoncreds object to indy object
        LOGGER.debug("Registering credential definition: %s", cred_def_id)
        indy_cred_def = {
            "id": cred_def_id,
            "issuerId": cred_def_id.split("/")[0],
            "schemaId": schema.schema_id,
            "credDefType": credential_definition.type,
            "tag": credential_definition.tag,
            "value": json.dumps(credential_definition.value.serialize()),
            # "ver": "1.0",
        }
        LOGGER.debug("Cred def value: %s", indy_cred_def)

        async with ledger:
            try:
                result = await shield(
                    ledger.send_credential_definition_anoncreds(
                        credential_definition.schema_id,
                        cred_def_id,
                        indy_cred_def,
                        write_ledger=True,
                        endorser_did=None,
                    )
                )
            except LedgerObjectAlreadyExistsError as err:
                if await issuer.credential_definition_in_wallet(cred_def_id):
                    raise AnonCredsObjectAlreadyExists(
                        f"Credential definition with id {cred_def_id} "
                        "already exists in wallet and on ledger.",
                        cred_def_id,
                    ) from err
                else:
                    raise AnonCredsObjectAlreadyExists(
                        f"Credential definition {cred_def_id} is on "
                        f"ledger but not in wallet {profile.name}",
                        cred_def_id,
                    ) from err
            except LedgerError as err1:
                raise AnonCredsRegistrationError("Something bad happened") from err1

            return CredDefResult(
                job_id=None,
                credential_definition_state=CredDefState(
                    state=CredDefState.STATE_FINISHED,
                    credential_definition_id=cred_def_id,
                    credential_definition=credential_definition,
                ),
                registration_metadata={},
                credential_definition_metadata={
                    "issuerId": "",
                    "seqNo": "besu",
                    **(options or {}),
                },
            )

    async def get_revocation_registry_definition(
        self, profile: Profile, rev_reg_def_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_reg_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsResolutionError(reason)

        async with ledger:
            rev_reg_def = await ledger.get_revoc_reg_def(rev_reg_def_id)

            if rev_reg_def is None:
                raise AnonCredsObjectNotFound(
                    f"Revocation registry definition not found: {rev_reg_def_id}",
                    {"ledger_id": ledger_id},
                )

            LOGGER.debug("Retrieved revocation registry definition: %s", rev_reg_def)
            rev_reg_def_value = RevRegDefValue.deserialize(rev_reg_def["value"])
            anoncreds_rev_reg_def = RevRegDef(
                issuer_id=rev_reg_def["issuerId"],
                cred_def_id=rev_reg_def["credDefId"],
                type=rev_reg_def["revocDefType"],
                value=rev_reg_def_value,
                tag=rev_reg_def["tag"],
            )
            result = GetRevRegDefResult(
                revocation_registry=anoncreds_rev_reg_def,
                revocation_registry_id=rev_reg_def["id"],
                resolution_metadata={},
                revocation_registry_metadata={},
            )

        return result

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        rev_reg_def_id = self.make_rev_reg_def_id(revocation_registry_definition)

        try:
            # Translate anoncreds object to indy object
            indy_rev_reg_def = {
                "ver": "1.0",
                "id": rev_reg_def_id,
                "revocDefType": revocation_registry_definition.type,
                "credDefId": revocation_registry_definition.cred_def_id,
                "tag": revocation_registry_definition.tag,
                "value": json.dumps(
                    {
                        "issuanceType": "ISSUANCE_BY_DEFAULT",
                        "maxCredNum": revocation_registry_definition.value.max_cred_num,
                        "publicKeys": revocation_registry_definition.value.public_keys,
                        "tailsHash": revocation_registry_definition.value.tails_hash,
                        "tailsLocation": revocation_registry_definition.value.tails_location,
                    }
                ),
                "issuerId": revocation_registry_definition.cred_def_id.split("/")[0],
            }

            abi = json.loads(REVOCATION_REGISTRY_ABI)
            address = self.web3.to_checksum_address(self.REVOCATION_ADDRESS)
            contract = self.web3.eth.contract(address=address, abi=abi)
            Chain_id = self.web3.eth.chain_id
            LOGGER.debug(f"Creating rev reg: {indy_rev_reg_def}")
            call_function = contract.functions.createRevocationRegistry(
                indy_rev_reg_def
            )

            try:
                estimated_gas = call_function.estimate_gas({"from": self.ACCOUNT})
                gas_limit = int(estimated_gas * 1.2)  # 20% safety margin
            except Exception as e:
                LOGGER.warning("Failed to estimate gas: %s. Using fallback from config.", e)
                gas_limit = int(self.REVOCATION_LIST_GAS_LIMIT)

            async with self._tx_lock:
                nonce = self.web3.eth.get_transaction_count(self.ACCOUNT)
                tx = call_function.build_transaction(
                    {
                        "chainId": Chain_id,
                        "from": self.ACCOUNT,
                        "nonce": nonce,
                        "gas": gas_limit,
                        "gasPrice": self.web3.eth.gas_price,
                    }
                )

                LOGGER.debug("Sending contract function %s: tuple %s", call_function.fn_name, call_function.arguments)
                tx_receipt = await self.send_transaction_tx(tx)

            # receipt = contract.functions.createSchema(indy_schema).transact({"from": self.ACCOUNT})
            LOGGER.debug("Receipt: %s", tx_receipt)
            # Was it realy created?
            try:
                contract.functions.resolveRevocation(rev_reg_def_id).call()
            except ContractCustomError as e:
                raise AnonCredsRegistrationError(
                    "Error searching for newly created revocation"
                ) from e

            seq_no = self.REVOCATION_ADDRESS
        except LedgerError as err:
            raise AnonCredsRegistrationError() from err

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=rev_reg_def_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={},
            revocation_registry_definition_metadata={"seqNo": seq_no},
        )

    async def _get_or_fetch_rev_reg_def_max_cred_num(
        self, profile: Profile, ledger: BaseLedger, rev_reg_def_id: str
    ) -> int:
        """Retrieve max cred num for a rev reg def.

        The value is retrieved from cache or from the ledger if necessary.
        The issuer could retrieve this value from the wallet but this info
        must also be known to the holder.
        """
        cache = profile.inject(BaseCache)
        cache_key = f"anoncreds::legacy_indy::rev_reg_max_cred_num::{rev_reg_def_id}"

        if cache:
            max_cred_num = await cache.get(cache_key)
            if max_cred_num:
                return max_cred_num

        rev_reg_def = await ledger.get_revoc_reg_def(rev_reg_def_id)
        max_cred_num = rev_reg_def["value"]["maxCredNum"]

        if cache:
            await cache.set(cache_key, max_cred_num)

        return max_cred_num

    def _indexes_to_bit_array(self, indexes: List[int], size: int) -> List[int]:
        """Turn a sequence of indexes into a full state bit array."""
        return [1 if index in indexes else 0 for index in range(0, size + 1)]

    async def _get_ledger(self, profile: Profile, rev_reg_def_id: str):
        async with profile.session() as session:
            multitenant_mgr = session.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(profile)
            else:
                ledger_exec_inst = session.inject(IndyLedgerRequestsExecutor)

        ledger_id, ledger = await ledger_exec_inst.get_ledger_for_identifier(
            rev_reg_def_id,
            txn_record_type=GET_CRED_DEF,
        )
        if not ledger:
            reason = "No ledger available"
            if not profile.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise AnonCredsResolutionError(reason)

        return ledger_id, ledger

    async def get_revocation_registry_delta(
        self, profile: Profile, rev_reg_def_id: str, timestamp: None
    ) -> Tuple[dict, int]:
        """Fetch the revocation registry delta."""
        ledger_id, ledger = await self._get_ledger(profile, rev_reg_def_id)

        async with ledger:
            delta, timestamp = await ledger.get_revoc_reg_delta(
                rev_reg_def_id, timestamp_to=timestamp
            )

            if delta is None:
                raise AnonCredsObjectNotFound(
                    f"Revocation list not found for rev reg def: {rev_reg_def_id}",
                    {"ledger_id": ledger_id},
                )
        LOGGER.debug("Retrieved delta: %s", delta)
        return delta, timestamp

    async def get_revocation_list(
        self, profile: Profile, rev_reg_def_id: str, timestamp: int
    ) -> GetRevListResult:
        """Get the revocation registry list."""
        _, ledger = await self._get_ledger(profile, rev_reg_def_id)
        delta, timestamp = await self.get_revocation_registry_delta(
            profile, rev_reg_def_id, timestamp
        )
        max_cred_num = await self._get_or_fetch_rev_reg_def_max_cred_num(
            profile, ledger, rev_reg_def_id
        )

        delta_list = delta["value"]["revoked"] if delta["value"].get("revoked") else []
        revocation_list_from_indexes = self._indexes_to_bit_array(
            delta_list, max_cred_num
        )
        LOGGER.debug(f"List of indexes {revocation_list_from_indexes}")
        rev_list = RevList(
            issuer_id=rev_reg_def_id.split("/")[0],
            rev_reg_def_id=rev_reg_def_id,
            revocation_list=revocation_list_from_indexes,  # rever isso depois
            current_accumulator=delta["value"]["accum"],
            timestamp=timestamp,
        )
        result = GetRevListResult(
            revocation_list=rev_list,
            resolution_metadata={},
            revocation_registry_metadata={},
        )

        return result

    async def _revoc_reg_entry_with_fix(
        self,
        profile: Profile,
        rev_list: RevList,
        rev_reg_def_type: str,
        entry: dict,
    ) -> dict:
        """Send a revocation registry entry to the ledger with fixes if needed."""
        try:
            # async with ledger:
            # rev_entry_res = await ledger.send_revoc_reg_entry(
            #     rev_list.rev_reg_def_id,
            #     rev_reg_def_type,
            #     entry,
            #     rev_list.issuer_id,
            #     write_ledger=True,
            #     endorser_did=None,
            # )
            abi = json.loads(REVOCATION_REGISTRY_ABI)
            address = self.web3.to_checksum_address(self.REVOCATION_ADDRESS)
            contract = self.web3.eth.contract(address=address, abi=abi)
            Chain_id = self.web3.eth.chain_id
            rev_entry = {
                "revDefId": rev_list.rev_reg_def_id,
                "regDefType": rev_reg_def_type,
                "entry": json.dumps(entry),
                "issuerId": rev_list.issuer_id,
            }
            call_function = contract.functions.createOrUpdateEntry(
                rev_entry
            )

            try:
                estimated_gas = call_function.estimate_gas({"from": self.ACCOUNT})
                gas_limit = int(estimated_gas * 1.2)  # 20% safety margin
            except Exception as e:
                LOGGER.warning("Failed to estimate gas: %s. Using fallback from config.", e)
                gas_limit = int(self.REVOCATION_LIST_GAS_LIMIT)

            async with self._tx_lock:
                nonce = self.web3.eth.get_transaction_count(self.ACCOUNT)
                tx = call_function.build_transaction(
                    {
                        "chainId": Chain_id,
                        "from": self.ACCOUNT,
                        "nonce": nonce,
                        "gas": gas_limit,
                        "gasPrice": self.web3.eth.gas_price,
                    }
                )

                LOGGER.debug("Sending contract function %s: tuple %s", call_function.fn_name, call_function.arguments)
                rev_entry_res = await self.send_transaction_tx(tx)

            rev_entry_res = contract.functions.resolveEntry(
                rev_list.rev_reg_def_id
            ).call()

            LOGGER.debug("Receipt: %s", rev_entry_res)

        except LedgerTransactionError as err:
            if "InvalidClientRequest" in err.roll_up:
                # ... if the ledger write fails (with "InvalidClientRequest")
                # e.g. aries_cloudagent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientRequest(...)
                # In this scenario we try to post a correction
                LOGGER.warn("Retry ledger update/fix due to error")
                LOGGER.warn(err)
                # (_, _, res) = await self.fix_ledger_entry(
                #     profile,
                #     rev_list,
                #     True,
                #     ledger.pool.genesis_txns,
                # )
                # rev_entry_res = {"result": res}
                LOGGER.warn("Ledger update/fix applied")
            elif "InvalidClientTaaAcceptanceError" in err.roll_up:
                # if no write access (with "InvalidClientTaaAcceptanceError")
                # e.g. aries_cloudagent.ledger.error.LedgerTransactionError:
                #   Ledger rejected transaction request: client request invalid:
                #   InvalidClientTaaAcceptanceError(...)
                LOGGER.exception("Ledger update failed due to TAA issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to TAA Issue"
                ) from err
            else:
                # not sure what happened, raise an error
                LOGGER.exception("Ledger update failed due to unknown issue")
                raise AnonCredsRegistrationError(
                    "Ledger update failed due to unknown issue"
                ) from err

        return rev_entry_res[0][0]

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        rev_reg_entry = {"ver": "1.0", "value": {"accum": rev_list.current_accumulator}}

        await self._revoc_reg_entry_with_fix(
            profile, rev_list, rev_reg_def.type, rev_reg_entry
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata={},
            revocation_list_metadata={
                "seqNo": "Besu",
            },
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
        unrevoke: bool = False,
    ) -> RevListResult:
        """Update a revocation list."""
        delta, _ = await self.get_revocation_registry_delta(
            profile, curr_list.rev_reg_def_id, 0
        )
        delta_list = delta["value"]["revoked"] if delta["value"].get("revoked") else []
        newly_revoked_indices = list(revoked)
        if unrevoke:
            full_revoked_list = set(delta_list) - set(newly_revoked_indices)
        else:
            full_revoked_list = newly_revoked_indices + delta_list
        rev_reg_entry = {
            "ver": "1.0",
            "value": {
                "accum": curr_list.current_accumulator,
                "prevAccum": prev_list.current_accumulator,
                "revoked": list(full_revoked_list),
            },
        }

        print(f"Entry: {rev_reg_entry}")

        await self._revoc_reg_entry_with_fix(
            profile, curr_list, rev_reg_def.type, rev_reg_entry
        )

        event_bus = profile.inject(EventBus)
        await event_bus.notify(
            profile,
            RevListFinishedEvent.with_payload(
                curr_list.rev_reg_def_id, newly_revoked_indices
            ),
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata={},
            revocation_list_metadata={
                "seqNo": "NA",
            },
        )

    async def fix_ledger_entry(
        self,
        profile: Profile,
        rev_list: RevList,
        apply_ledger_update: bool,
        genesis_transactions: str,
    ) -> Tuple[dict, dict, dict]:
        """Fix the ledger entry to match wallet-recorded credentials."""
        # get rev reg delta (revocations published to ledger)
        ledger = profile.inject(BaseLedger)
        async with ledger:
            (rev_reg_delta, _) = await ledger.get_revoc_reg_delta(
                rev_list.rev_reg_def_id
            )

        # get rev reg records from wallet (revocations and list)
        recs = []
        rec_count = 0
        accum_count = 0
        recovery_txn = {}
        applied_txn = {}
        async with profile.session() as session:
            recs = await IssuerCredRevRecord.query_by_ids(
                session, rev_reg_id=rev_list.rev_reg_def_id
            )

            revoked_ids = []
            for rec in recs:
                if rec.state == IssuerCredRevRecord.STATE_REVOKED:
                    revoked_ids.append(int(rec.cred_rev_id))
                    if int(rec.cred_rev_id) not in rev_reg_delta["value"]["revoked"]:
                        # await rec.set_state(session, IssuerCredRevRecord.STATE_ISSUED)
                        rec_count += 1

            LOGGER.debug(">>> fixed entry recs count = %s", rec_count)
            LOGGER.debug(
                ">>> rev_list.revocation_list: %s",
                rev_list.revocation_list,
            )
            LOGGER.debug(
                '>>> rev_reg_delta.get("value"): %s', rev_reg_delta.get("value")
            )

            # if we had any revocation discrepencies, check the accumulator value
            if rec_count > 0:
                if (rev_list.current_accumulator and rev_reg_delta.get("value")) and (
                    rev_list.current_accumulator != rev_reg_delta["value"]["accum"]
                ):
                    # self.revoc_reg_entry = rev_reg_delta["value"]
                    # await self.save(session)
                    accum_count += 1

                calculated_txn = await generate_ledger_rrrecovery_txn(
                    genesis_transactions,
                    rev_list.rev_reg_def_id,
                    revoked_ids,
                )
                recovery_txn = json.loads(calculated_txn.to_json())

                LOGGER.debug(">>> apply_ledger_update = %s", apply_ledger_update)
                if apply_ledger_update:
                    ledger = session.inject_or(BaseLedger)
                    if not ledger:
                        reason = "No ledger available"
                        if not session.context.settings.get_value("wallet.type"):
                            reason += ": missing wallet-type?"
                        raise LedgerError(reason=reason)

                    async with ledger:
                        ledger_response = await ledger.send_revoc_reg_entry(
                            rev_list.rev_reg_def_id, "CL_ACCUM", recovery_txn
                        )

                    applied_txn = ledger_response["result"]

        return (rev_reg_delta, recovery_txn, applied_txn)
