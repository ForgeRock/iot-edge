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

package mocks

// MockSession mocks a session.Session
type MockSession struct {
	TokenFunc  func() string
	ValidFunc  func() (bool, error)
	LogoutFunc func() error
}

func (s *MockSession) Token() string {
	if s.TokenFunc != nil {
		return s.TokenFunc()
	}
	return ""
}

func (s *MockSession) Valid() (bool, error) {
	if s.ValidFunc != nil {
		return s.ValidFunc()
	}
	return true, nil
}

func (s *MockSession) Logout() error {
	if s.LogoutFunc != nil {
		return s.LogoutFunc()
	}
	return nil
}
