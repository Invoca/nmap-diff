package mocks

import "github.com/stretchr/testify/mock"

type ResettableMock struct {
	mock.Mock
}

func (m *ResettableMock) Reset() {
	m.ExpectedCalls = []*mock.Call{}
}
