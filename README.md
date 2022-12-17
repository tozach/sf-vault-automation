## What the script does
The script, `create-vault.py`, automates the creation of a Vault and associated roles, policies, service accounts and their assignments. The script uses a configuration file (vault-config.json) to drive this.

The `vault-config.json` file requires -
1. One vault definition
2. Multiple roles associated to the Vault
3. Multiple policies associated to each role
4. One service account for each role

Considerations to make -
1. The config file should have one of "pat" or "creds-file". pat is the Personal Access Token that can be generated from the Studio (only in Try). The creds file should be of a service account that has access to create vaults
2. Do not pass a "user-id" if "pat" is used. The "user-id" is to allow the VAULT_OWNER role of the new Vault to be assigned to a specific User. This is not mandatory but it will allow the vault to be visible for the individual user when the user logs in to Studio
3. The policy definitions in the config file are not validated by the script. It is recommended to first create the policy in a lower environment and use that policy definition in the config file. It is possible that a policy creation API call returns a successful response but that it doesn't enforce the policy as intended. The policy definitions will need slight adjustment in such scenarios. Tt is recommended to test the script in a dev environment first to verify that it works as expected
4. The service account creds files are written to the logs. There is an option to also upload it to an AWS SM. It requires that the envrionment from which the script is being run is already set up with AWS auth