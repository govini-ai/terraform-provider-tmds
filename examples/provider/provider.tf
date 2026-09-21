terraform {
  required_providers {
    tmds = {
      source  = "govini-ai/tmds"
      version = "~> 0.1"
    }
  }
}

# Endpoint + key are typically supplied via TMDS_ENDPOINT / TMDS_API_KEY
# (pulled from Secrets Manager) rather than hardcoded.
provider "tmds" {
  endpoint = "https://dsm.example.com"
  # api_key = var.tmds_api_key   # sensitive — source from Secrets Manager
  insecure = false
}
