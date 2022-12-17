import requests
import json
import time
import jwt
import boto3
from botocore.exceptions import ClientError

def getSignedJWT(credsFile):
   # credsFile is the filepath to your credentials.json file
   # Load the credentials.json file into an object called creds
   fd = open(credsFile)
   creds = json.load(fd)
   fd.close()
   
   # Create the claims object with the data in the creds object
   claims = {
       "iss": creds["clientID"],
       "key": creds["keyID"], 
       "aud": creds["tokenURI"], 
       "exp": int(time.time()) + (3600), # JWT expires in Now + 60 minutes
       "sub": creds["clientID"], 
   }
   # Sign the claims object with the private key contained in the creds object
   signedJWT = jwt.encode(claims, creds["privateKey"], algorithm='RS256') 
   return signedJWT, creds  

def getBearerToken(signedJWT, creds):
   # Request body parameters
   body = {
       'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
       'assertion': signedJWT,
   }
   tokenURI = creds["tokenURI"]
   clientName = creds["clientName"]
   
   # Send the POST request using your favorite Python HTTP request lib
   r = requests.post(tokenURI, json=body)
   return r.text

def loadVaultSchemaFromFile(vaultSchema):
   # vaultSchema is the filepath to schema file
   # Load the schema file into an object called schema
   vs = open(vaultSchema)
   schema = json.load(vs)
   vs.close()
   return schema

def createVaultFromSchema(vaultName, vaultDescription, vaultDisplayName, vaultSchemaLoc, accountID, workspaceID, bearerToken = None, manageUrl = None):
   
   vaultName = vaultName
   vaultDescription = vaultDescription
   workspaceID = workspaceID
   manageUrl = manageUrl+"vaults"
   schemaPayload =  {
        "name": vaultName,
        "description": vaultDescription,
        "vaultSchema": loadVaultSchemaFromFile(vaultSchemaLoc),
        "workspaceID": workspaceID
   }

   payload = json.dumps(schemaPayload)
   authHeader = "Bearer "+ bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = (requests.request("POST", manageUrl, headers=headers, data=payload))
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)
      
   return response.text

def createPolicy(policyObj, accountId, vaulId, bearerToken, manageUrl = None):
   manageUrl = manageUrl+"policies"
   rulesParams=[]
   for rp in policyObj["ruleParams"]:
      if "redaction" in rp["columnRuleParams"]:
         ruleParamsTemp =   {
            "name": rp["name"],
            "ruleExpression": rp["ruleExpression"],
            "columnRuleParams": {
               "vaultID": vaulId,
               "columns": rp["columnRuleParams"]["columns"],
               "action": rp["columnRuleParams"]["action"],
               "effect": rp["columnRuleParams"]["effect"],
               "redaction": rp["columnRuleParams"]["redaction"],
            }
         }
      else:
         ruleParamsTemp =   {
                     "name": rp["name"],
                     "ruleExpression": rp["ruleExpression"],
                     "columnRuleParams": {
                        "vaultID": vaulId,
                        "columns": rp["columnRuleParams"]["columns"],
                        "action": rp["columnRuleParams"]["action"],
                        "effect": rp["columnRuleParams"]["effect"]
                     }
                  }
      rulesParams.append(ruleParamsTemp)

   policyPayload =  {
        "name": policyObj["name"],
        "displayName": policyObj["name"],
        "description": policyObj["description"],
        "resource": {
          "ID": vaulId,
          "type": "VAULT"
         },
        "ruleParams": rulesParams
   }
   
   payload = json.dumps(policyPayload)   
   authHeader = "Bearer "+ bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountId
   try:
      response = requests.request("POST", manageUrl, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)   
   return response.text

def createRole(r, accountId, vaultId, bearerToken, manageUrl = None):
   
   manageUrl = manageUrl+"roles"
   schemaPayload =  {
        "roleDefinition": {
            "name": r["name"],
            "displayName": r["name"],
            "description": r["description"],
            "permissions": r["permissions"],
            "levels": [
                "vault"
            ],
            "type": "CUSTOM",
            "internal": False,
        },
        "resource": {
            "ID": vaultId,
            "type": "VAULT"
        }
    }

   payload = json.dumps(schemaPayload)
   authHeader = "Bearer "+ bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountId
   try:
      response = requests.request("POST", manageUrl, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)      
   return response.text

def assignPolicy(policyID, roleID, bearerToken, accountID = None, manageUrl = None):
   url = manageUrl+"policies/assign"
   
   payload = json.dumps({
     "ID": policyID,
     "roleIDs": [
       roleID
     ]
   })
   authHeader = "Bearer "+ bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader 
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = requests.request("POST", url, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)

   return response.text

def enablePolicy(policyID, bearerToken = None, accountID = None, manageUrl = None):
   url = manageUrl+"policies/"+policyID+"/status"
   
   payload = json.dumps({
     "ID": policyID,
     "status": "ACTIVE"
   })
   if bearerToken == "" or bearerToken == None:
      jwtToken, creds = getSignedJWT('/Users/toms/Downloads/vault-creator.json')
      bearerToken = json.loads(getBearerToken(jwtToken, creds))
      token = ((bearerToken['accessToken']))
   else:
      token = bearerToken
   authHeader = "Bearer "+ token
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = requests.request("PATCH", url, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)

   return response.text

def createServiceAccount(vaultID, saName, description, roleID, accountID, bearerToken = None, manageUrl = None):
   url = manageUrl+"serviceAccounts"
   saName = saName
   description = description
   displayName = saName

   payload = json.dumps({
     "resource": {
     "ID": vaultID,
     "type": "VAULT"
     },
     "serviceAccount": {
       "name": saName,
       "displayName": displayName,
       "description": description
       }
    })
   if bearerToken == "" or bearerToken == None:
      jwtToken, creds = getSignedJWT('/Users/toms/Downloads/vault-creator.json')
      bearerToken = json.loads(getBearerToken(jwtToken, creds))
      token = ((bearerToken['accessToken']))
      print("using PAT ...")
   else:
      token = bearerToken
   authHeader = "Bearer "+ token
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = requests.request("POST", url, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)

   return response.text

def updateAwsSecret(secretName, creds):

    secretName = secretName
    regionName = "us-east-1"
    secret = creds

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=regionName
    )

    try:
        update_secret_value_response = client.update_secret(
            SecretId=secretName,
            SecretString=json.dumps(secret)
        )
        return update_secret_value_response
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e
    
def assignRole(assignID, type, roleID, bearerToken = None, accountID = None, manageUrl = None):
   url = manageUrl+"roles/assign"
   
   payload = json.dumps({
   "ID": roleID,
   "members": [
      {
         "ID": assignID,
         "type": type
      }]
   })

   authHeader = "Bearer "+ bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader 
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = requests.request("POST", url, headers=headers, data=payload)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)
   return response.text

def getRoles(vaultId, type, bearerToken, accountID, manageUrl):   
   url = manageUrl+"roles?"+"resource.type="+type+"&resource.ID="+vaultId

   authHeader = "Bearer " + bearerToken
   headers={}
   headers["Accept"] = "application/json"
   headers["Authorization"] = authHeader 
   headers["X-SKYFLOW-ACCOUNT-ID"] = accountID
   try:
      response = requests.request("GET", url, headers=headers)
      response.raise_for_status()
   except requests.exceptions.HTTPError as errh:
      print ("HTTP Error: ",errh)
   except requests.exceptions.ConnectionError as errc:
      print ("Error Connecting: ",errc)
   except requests.exceptions.Timeout as errt:
      print ("Timeout Error: ",errt)
   except requests.exceptions.RequestException as err:
      print ("Unknown error: ",err)
   return response.text

def loadVaultConfig(confFile):
   # credsFile is the filepath to your credentials.json file
   # Load the credentials.json file into an object called creds
   fd = open(confFile)
   conf = json.load(fd)
   fd.close()
   return conf

vaultConf = loadVaultConfig('vault-config.json')
accountId = vaultConf["vault"]["account-id"]
vaultName = vaultConf["vault"]["name"]
vaultDescription = vaultConf["vault"]["description"]
vaultDisplayName = vaultConf["vault"]["display-name"]
workspaceId = vaultConf["vault"]["workspace-id"]
vaultSchemaLoc = vaultConf["vault"]["schema-location"]
manageUrl = vaultConf["vault"]["manage-url"]
rolesDef = vaultConf["vault"]["roles"]

if vaultConf["vault"]["pat"] != "":
  print("Using pat for authentication")
  accessToken = vaultConf["vault"]["pat"]
elif vaultConf["vault"]["creds-file"] != "":
  print("Using creds file for authentication")
  jwtToken, creds = getSignedJWT(vaultConf["vault"]["creds-file"])
  bearerToken = json.loads(getBearerToken(jwtToken, creds))
  accessToken = ((bearerToken['accessToken']))
else:
  #print("Missing authentication details. Exiting process")
  raise SystemExit('Missing authentication details. Exiting process')

print("Creating Vault ... " + vaultConf["vault"]["name"])
createVaultStatus = createVaultFromSchema(vaultName, vaultDescription, vaultDisplayName, vaultSchemaLoc, accountId, workspaceId, accessToken, manageUrl)
createVaultStatusRes = json.loads(createVaultStatus)
print(createVaultStatus)
try:
   vaultId = createVaultStatusRes['ID']
   print("Created Vault: " + vaultId)
except:
   print("Error creating Vault: " + str(createVaultStatusRes))
   raise Exception("Error creating Vault: " + str(createVaultStatusRes)) 

for r in vaultConf["vault"]["roles"]:
   print("Creating role: " + r["name"])
   createRoleRes = json.loads(createRole(r, accountId, vaultId, accessToken, manageUrl))
   print("Created role: " + str(createRoleRes))
   try:
      roleID = createRoleRes['ID']
      print("Created role: " + roleID)
   except:
      print("Error creating log reader role: " + str(createRoleRes))
      raise Exception("Error creating log reader role: " + str(createRoleRes))    
   for p in r["policies"]:
      # Create policies
      print("Creating policy " + p["name"] )
      createPolicyResponse = json.loads(createPolicy(p, accountId, vaultId, accessToken, manageUrl))
      try:
         policyID = createPolicyResponse['ID']
         print("Created policy: " + policyID)
      except:
         print("Error creating policy: " + str(createPolicyResponse))
         raise Exception("Error creating policy: " + str(createPolicyResponse))
      
      # Assign policies
      print("Assigning policy: "+policyID+" to role: "+roleID+ " ...")
      assignPolicyRes = json.loads(assignPolicy(policyID, roleID, accessToken, accountId, manageUrl))
      print(assignPolicyRes)
      try:
         policyIDA = assignPolicyRes['ID']
         print("Assigned policy:  "+policyIDA+" to log reader role: "+roleID)
      except:
         print("Error assigning policy: " + str(assignPolicyRes))
         raise Exception("Error assigning log reader policy: " + str(assignPolicyRes))
      
      # Enable policies
      print("Enabling policy: "+policyID+ " ...")
      enablePolicyRes = json.loads(enablePolicy(policyID, accessToken, accountId, manageUrl))
      print(enablePolicyRes)
      try:
         policyIDE = enablePolicyRes['ID']
         print("Enabled policy: "+policyIDE)
      except:
         print("Error enabling policy: " + str(enablePolicyRes))
         raise Exception("Error enabling policy: " + str(enablePolicyRes))
   
   # Create service account
   print("Creating service account ..." + r["service-account"]["name"])
   createServiceAccountRes = json.loads(createServiceAccount(vaultId, r["service-account"]["name"], r["service-account"]["description"], roleID, accountId, accessToken, manageUrl))
   print(createServiceAccountRes)
   try:
      clientId = createServiceAccountRes['clientID']
      print("Created Service Account with ClientID: "+ clientId)
   except:
      print("Error creating service account: " + str(createServiceAccountRes))
      raise Exception("Error creating service account: " + str(createServiceAccountRes))

   # Assign role to service account
   print("Assigning role: "+roleID+" to service account: "+clientId+ " ...")
   assignRoleToSARes = json.loads(assignRole(clientId, "SERVICE_ACCOUNT", roleID, accessToken, accountId, manageUrl))
   print(assignRoleToSARes)
   try:
      policyIDA = assignRoleToSARes['ID']
      print("Assigned policy:  "+policyIDA+" to role: "+roleID)
   except:
      print("Error assigning role: " + str(assignRoleToSARes))
      raise Exception("Error assigning policy: " + str(assignRoleToSARes))      

# Assign UI user to Vault owner role
if vaultConf["vault"]["user-id"] != "":
  print("Fetching roles for the new Vault")
  rolesRes = json.loads(getRoles(vaultId, "VAULT", accessToken, accountId, manageUrl))
  try:
      for r in rolesRes["roles"]:
         if r["definition"]["name"] == "VAULT_OWNER":
            roleId = r["ID"]
            print("Vault Owner Id is: "+roleId)
            break
  except:
      print("Error fetching Vault Owner roles: " + str(rolesRes))
      raise Exception("Error fetching roles: " + str(rolesRes))
  
  # Assign role to User
  print("Assigning role: "+roleID+" to user: "+vaultConf["vault"]["user-id"]+ " ...")
  assignRoleToUserRes = json.loads(assignRole(vaultConf["vault"]["user-id"], "USER", roleID, accessToken, accountId, manageUrl))
  print(assignRoleToUserRes)
  try:
     userIdA = assignRoleToUserRes['ID']
     print("Assigned role:  "+userIdA+" to user: "+vaultConf["vault"]["user-id"])
  except:
     print("Error assigning role: " + str(assignRoleToUserRes))
     raise Exception("Error assigning policy: " + str(assignRoleToUserRes))   
else:
   print("Skipping UI user assignment as user-id is empty")

"""
# Upload secret to AWS SM
try:
   credsRes = updateAwsSecret(awsSecretName, createServiceAccountLRes)
   print(credsRes)
except:
   print("Error uploading secrets to AWS SM")
"""