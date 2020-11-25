terraform {
  required_providers {
    dns-gssapi = {
      versions = ["0.2"]
      source   = "github.com/trevex/dns-gssapi"
    }
  }
}

variable "password" {
  type = string
}

provider "dns-gssapi" {
  ip       = "10.18.52.20"
  hostname = "vm---ad01.envdevel.lan"
  port     = 53
  realm    = "ENVDEVEL.LAN"
  username = "DNSUpdate"
  password = var.password
}

resource "dns_record_set" "test" {
  provider = dns-gssapi

  zone    = "envdevel.lan"
  name    = "anothertestentry2"
  type    = "A"
  rrdatas = ["192.168.9.2"]
}
