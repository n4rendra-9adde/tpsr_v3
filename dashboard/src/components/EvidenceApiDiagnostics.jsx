import React from 'react';
import { Collapse, List, Tag, Typography } from 'antd';

const { Text } = Typography;
const { Panel } = Collapse;

export function EvidenceApiDiagnostics({ diagnostics }) {
  if (process.env.NODE_ENV !== 'development' || !diagnostics || diagnostics.length === 0) {
    return null;
  }

  return (
    <Collapse style={{ marginBottom: 16 }}>
      <Panel header="Evidence API Diagnostics (Development Only)" key="1">
        <List
          size="small"
          dataSource={diagnostics}
          renderItem={(item) => (
            <List.Item>
              <div style={{ width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text strong>{item.endpoint}</Text>
                  <Tag color={item.status === 200 ? 'green' : 'red'}>HTTP {item.status}</Tag>
                </div>
                <div>
                  <Text type="secondary">Records: {item.count}</Text>
                </div>
                {item.emptyReason && (
                  <div>
                    <Text type="warning">Empty State Reason: {item.emptyReason}</Text>
                  </div>
                )}
                {item.parseError && (
                  <div>
                    <Text type="danger">Parse Error: {item.parseError}</Text>
                  </div>
                )}
              </div>
            </List.Item>
          )}
        />
      </Panel>
    </Collapse>
  );
}
