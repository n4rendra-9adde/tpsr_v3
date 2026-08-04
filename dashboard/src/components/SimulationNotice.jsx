import React from 'react';
import { Alert } from 'antd';

export function SimulationNotice() {
  return (
    <Alert
      type="warning"
      showIcon
      message={<strong style={{ fontSize: '16px' }}>SIMULATION ONLY</strong>}
      description="This result is not persisted and does not change the authoritative trust decision or lifecycle state."
      style={{ marginBottom: 16, borderLeft: '6px solid #faad14' }}
    />
  );
}
