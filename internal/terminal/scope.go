package terminal

// ActiveCount supports fail-closed local mode changes. New task starts are
// serialized by the Runtime tool gate while the local mode setter holds its lock.
func (m *TaskManager) ActiveCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tasks {
		t.mu.Lock()
		if t.Status == TaskRunning {
			n++
		}
		t.mu.Unlock()
	}
	return n
}
