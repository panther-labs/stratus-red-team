// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// TerraformManager is an autogenerated mock type for the TerraformManager type
type TerraformManager struct {
	mock.Mock
}

// Initialize provides a mock function with no fields
func (_m *TerraformManager) Initialize() {
	_m.Called()
}

// TerraformDestroy provides a mock function with given fields: directory
func (_m *TerraformManager) TerraformDestroy(directory string) error {
	ret := _m.Called(directory)

	if len(ret) == 0 {
		panic("no return value specified for TerraformDestroy")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(directory)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TerraformInitAndApply provides a mock function with given fields: directory, vars
func (_m *TerraformManager) TerraformInitAndApply(directory string, vars map[string]string) (map[string]string, error) {
	ret := _m.Called(directory, vars)

	if len(ret) == 0 {
		panic("no return value specified for TerraformInitAndApply")
	}

	var r0 map[string]string
	var r1 error
	if rf, ok := ret.Get(0).(func(string, map[string]string) (map[string]string, error)); ok {
		return rf(directory, vars)
	}
	if rf, ok := ret.Get(0).(func(string, map[string]string) map[string]string); ok {
		r0 = rf(directory, vars)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	if rf, ok := ret.Get(1).(func(string, map[string]string) error); ok {
		r1 = rf(directory, vars)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewTerraformManager creates a new instance of TerraformManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTerraformManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *TerraformManager {
	mock := &TerraformManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
