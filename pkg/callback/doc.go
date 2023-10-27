/*
 * Copyright 2020-2023 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package callback provides types for handling authentication callbacks. Use the predefined callback handlers to
// process callbacks received from Access Management's authentication framework or use the Handler interface to
// provide your own handler.
//
// This is an example of how to create your own callback handler:
//
//	type ThingHandler struct {
//	    ThingInput string
//	}
//
//	func (h ThingHandler) Handle(cb callback.Callback) (bool, error) {
//	    if cb.Type != "ThingCallback" {
//	        return false, nil
//	    }
//	    cb.Input[0].Value = h.ThingInput
//	    return true, nil
//	}
//
// The handler can then be used during the authentication process of a thing or session:
//
//	builder.Thing().HandleCallbacksWith(ThingHandler{ThingInput: "value"})
package callback
