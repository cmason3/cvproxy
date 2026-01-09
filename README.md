![Python](https://img.shields.io/badge/python-≥&nbsp;3.10-brightgreen)

# Arista CloudVision Proxy

Arista are transitioning their CloudVision provisioning model to use Studios and Workspaces, but the HTTP REST API only supports the legacy provisioning model, which has now been deprecated. The new API uses gRPC and is rather complex, but Arista provides a Python library to talk to the API, which is used by Ansible via the `arista.avd.cv_deploy` role. The purpose of this tool is to use `pyavd` to handle the complexity and to provide a HTTP proxy to convert between simplified JSON and gRPC using the same workflow that Ansible uses via `pyavd._cv.workflows.deploy_to_cv`.

### Installation

```
python3 -m pip install --upgrade cvproxy
```

### Usage

```
 cvproxy -s [-l <address>] [-p <port>] [-xff]

   -s                         - start CVProxy
   -l <address>               - specify a listen address (default is '127.0.0.1')
   -p <port>                  - specify a listen port (default is 8080)
   -xff                       - use X-Forwarded-For
```

It works by accepting a HTTP POST request with a `Content-Type` of `application/json`, which should adhere to the following schema:

```json
"unevaluatedProperties": false,
"required": ["devices", "cv_server", "cv_token"],
"properties": {
  "devices": {
    "minProperties": 1,
    "unevaluatedProperties": false,
    "patternProperties": {
      "^[a-z][a-z0-9_.-]*$": {
        "unevaluatedProperties": false,
        "required": ["configlet"],
        "properties": {
          "serial_number": { "type": "string", "pattern": "^[A-Z][A-Z0-9]{10}$" },
          "configlet": { "type": "string", "pattern": "^(?=(.{4})+$)[A-Za-z0-9+/-]+={0,2}$" }
        }
      }
    }
  },
  "cv_server": { "type": "string", "minLength": 1 },
  "cv_token": { "type": "string", "minLength": 1 },
  "cv_change_control_name": { "type": "string", "minLength": 1 },
  "cv_delete_workspace": { "type": "boolean" }
}
```

The `serial_number` attribute is optional as it should be able to identify the device based on the hostname, unless it is a new device and there is no existing configlet.
The `configlet` attribute is mandatory and is the configlet for the device, which must be Base64 encoded.

Example:

```json
"devices": {
  "leaf-1a": {
    "configlet": "<base64 encoded configlet>"
  },
  "leaf-1b": {
    "configlet": "<base64 encoded configlet>"
  }
},
"cv_server": "www.cv-prod-uk-1.arista.io",
"cv_token": "<service token>"
```

If the HTTP POST request succeeds and there are any changes then a Change Control will be created in CloudVision ready for you to review and approve.
The `cv_change_control_name` attribute is optional and if not provided will use the AVD default.
The `cv_delete_workspace` attribute is also optional and if set to "true" will cleanup and delete the submitted Workspace.

Successful HTTP responses will be JSON encoded and will always contain a `status` attribute, which will either be "ok" or "error".
If it is set to "ok" then an optional `change_control` attribute will be included if a Change Control was generated.
If it is set to "error" then an `errors` attribute will also be provided with details of why it failed.

The recommended deployment is to deploy HAProxy in front of CVProxy, as HAProxy is better equipped to deal with TLS termination and it also supports HTTP/2 and HTTP/3 transports.
