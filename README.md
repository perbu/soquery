# soquery

Read-only SOQL queries against Salesforce, output as markdown. Designed as an AI agent tool.

```
soquery "SELECT Id, Name FROM Account LIMIT 5"
```

```
| Id | Name |
| --- | --- |
| 001xx000003DGbY | Acme Corp |
| 001xx000003DGbZ | Globex |
```

## Install

```
go install github.com/perbu/soquery@latest
```

Or build from source:

```
go build -o soquery .
```

## Auth

Set credentials via environment variables or a `.env` file in the working directory.

```
SALESFORCE_DOMAIN=mycompany.my.salesforce.com
SALESFORCE_CONSUMER_KEY=3MVG9...
SALESFORCE_CONSUMER_SECRET=...
```

The tool fetches a token automatically on each invocation using the OAuth2 client credentials flow. See below for setup.

## Salesforce Connected App Setup

This creates a service account with restricted, read-only API access.

### 1. Create a restricted profile

- **Setup > Users > Profiles**
- Clone "Minimum Access - Salesforce" (or "Read Only")
- Name it something like `API Read Only`
- Edit the profile:
  - **System Permissions**: enable "API Enabled"
  - **Object Permissions**: grant Read on only the objects you need (Account, Contact, etc.)
  - Remove everything else

### 2. Create a service user

- **Setup > Users > Users > New User**
- License: Salesforce / Salesforce Integration
- Profile: the one you just created
- Email: a team alias or shared inbox
- Username must be globally unique (e.g. `soquery@yourcompany.com.api`)

### 3. Create the Connected App

- **Setup > App Manager > New Connected App**
- Fill in name/contact email
- **Enable OAuth Settings**:
  - Callback URL: `https://localhost` (unused but required)
  - Selected OAuth Scopes: add `Manage user data via APIs (api)`
- Save, then wait a few minutes for it to propagate

### 4. Enable Client Credentials flow

- Back in **App Manager**, find your app, click the dropdown arrow > **Manage**
- Click **Edit Policies**
  - Under "Client Credentials Flow", set **Run As** to the service user you created
- Save
- Go back to **App Manager**, click the dropdown arrow > **View**
  - Copy **Consumer Key** (this is `SALESFORCE_CONSUMER_KEY`)
  - Click "Manage Consumer Details", verify identity, copy **Consumer Secret** (this is `SALESFORCE_CONSUMER_SECRET`)

### 5. Test

```
export SALESFORCE_DOMAIN="mycompany.my.salesforce.com"
export SALESFORCE_CONSUMER_KEY="<Consumer Key>"
export SALESFORCE_CONSUMER_SECRET="<Consumer Secret>"
soquery "SELECT Id, Name FROM Account LIMIT 5"
```
