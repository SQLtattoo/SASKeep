#!/bin/bash

#login if needed, you can leverage Azure Cloud Shell
az login

#check security login context
az account show --output table

# Variables
#you can change to desired settings to comply with your organization and permissions as needed
resourceGroupName="<your resource group name here>"
location="<the Azure region you want to deploy the Azure Key Vault>"
keyVaultName="kvSASKeep" 
appName="SASKeep" 

# Create Resource Group
az group create --name $resourceGroupName --location $location

# Create Key Vault
az keyvault create --name $keyVaultName --resource-group $resourceGroupName --location $location

### Define app registration name, etc.
clientid=$(az ad app create --display-name $appName --query appId --output tsv)
objectid=$(az ad app show --id $clientid --query id --output tsv)

###Add client secret with expiration. The default is one year.
clientsecretname=mySecret
clientsecretduration=1 
clientsecret=$(az ad app credential reset --id $clientid --append --display-name $clientsecretname --years $clientsecretduration --query password --output tsv)
echo $clientsecret

###Create an AAD service principal
az ad sp create --id $clientid

###Look up a service principal
spid=$(az ad sp show --id $clientid --query id --output tsv)


# Assign permissions for Service Principal to Key Vault
az keyvault set-policy --name $keyVaultName --object-id $spid --secret-permissions get set

#set the configuration secrets for your storage account
# IMPORTANT: DO NOT SAVE these values in your file. Just input these in the runtime. Otherwise it is a security risk your imposing.
az keyvault secret set --vault-name $keyVaultName --name "accountName"  --value "<storage_account_name>"
az keyvault secret set --vault-name $keyVaultName --name "accountConnectionString"  --value "<storage_account_connection_string>"
az keyvault secret set --vault-name $keyVaultName --name "accountKey"  --value "<storage_account_key>"

