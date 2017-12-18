# Safe password
Store and check passwords as of current standards told you to

## HOW TO

### Zero setup

```typescript

import {SafePasswordHelper} from "safe-password";

// Create result as a ready-made encrypted password
const result = await SafePasswordHelper
                     .get()
                     .standard()
                     .encodeAuto("password");

// Check some password on validity against result
const valid = await SafePasswordHelper
                       .get()
                       .standard()
                       .checkAuto("password", result);
                                    
if(valid) {
    
    // .... Do something
    
}

```
