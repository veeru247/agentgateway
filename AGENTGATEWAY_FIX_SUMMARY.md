# AgentGateway MCP HTTP Authentication Fix

## Overview
This document summarizes the fix implemented for MCP HTTP authentication header forwarding in the AgentGateway project.

## Problem Statement
The AgentGateway was not properly forwarding authentication headers to backend MCP HTTP services, even when the `passthrough` configuration was enabled. This caused authentication failures when trying to access protected MCP endpoints.

## Root Cause
The issue was in the `crates/agentgateway_mcp_client/src/transports/http.rs` file. The code was only passing the Authorization header when `backendAuth.passthrough` was disabled (i.e., when using static auth), but not when passthrough was enabled.

## Solution
Modified the authentication header forwarding logic in the `make_request` method to:
1. Check if `backendAuth.passthrough` is enabled
2. If enabled, extract the Authorization header from the incoming request
3. Forward the Authorization header to the backend MCP service

### Code Changes
**File**: `crates/agentgateway_mcp_client/src/transports/http.rs`

The key change was in the request building logic:

```rust
// Only pass Authorization header when backendAuth.passthrough is enabled
if let Some(backend_auth) = &self.backend_auth {
    if backend_auth.passthrough {
        if let Some(auth_header) = headers.get("authorization") {
            request_builder = request_builder.header("Authorization", auth_header);
        }
    }
}
```

This ensures that when `passthrough: true` is configured in the backend authentication settings, the Authorization header from the incoming request is forwarded to the backend MCP HTTP service.

## Configuration
To use this feature, configure your MCP HTTP transport with:

```yaml
backendAuth:
  passthrough: true
```

## Testing
The fix has been tested with:
- Auth0 authenticated MCP endpoints
- Bearer token authentication
- Various MCP tool invocations through the gateway

## Impact
- Enables proper authentication for protected MCP HTTP endpoints
- Maintains backward compatibility with static authentication
- Allows secure access to enterprise MCP services requiring user-level authentication

## Related Files
- `crates/agentgateway_mcp_client/src/transports/http.rs` - Main fix implementation
- `sample-commerce-auth0.yaml` - Example configuration for Auth0 protected MCP endpoints
