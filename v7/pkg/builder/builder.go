/*
 * Copyright 2020 ForgeRock AS
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

package builder

import (
	isession "github.com/ForgeRock/iot-edge/v7/internal/session"
	ithing "github.com/ForgeRock/iot-edge/v7/internal/thing"
	"github.com/ForgeRock/iot-edge/v7/pkg/session"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

// Thing returns a new Thing builder.
func Thing() thing.Builder {
	return &ithing.BaseBuilder{}
}

// Session returns a new Session builder.
func Session() session.Builder {
	return &isession.Builder{}
}
