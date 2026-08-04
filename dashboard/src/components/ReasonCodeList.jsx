import React from 'react';
import { List, Typography } from 'antd';

const { Text } = Typography;

export function ReasonCodeList({ reasonCodes }) {
  if (!reasonCodes || reasonCodes.length === 0) {
    return null;
  }

  return (
    <List
      size="small"
      header={<div><b>Reason Codes</b></div>}
      bordered
      dataSource={reasonCodes}
      renderItem={item => (
        <List.Item>
          <Text strong style={{ marginRight: 8 }}>{item.code}</Text>
          <Text>{item.message}</Text>
          {item.details && <Text type="secondary" style={{ marginLeft: 8 }}>({item.details})</Text>}
        </List.Item>
      )}
    />
  );
}
