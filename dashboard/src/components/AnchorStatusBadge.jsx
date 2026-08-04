import React from 'react';
import { Tag } from 'antd';

export function AnchorStatusBadge({ status }) {
  let color = 'default';
  if (status === 'REGISTERED') color = 'default';
  else if (status === 'REVIEW_PENDING') color = 'orange';
  else if (status === 'SECURITY_REVIEWED') color = 'cyan';
  else if (status === 'COMPLIANT') color = 'geekblue';
  else if (status === 'APPROVED') color = 'blue';
  else if (status === 'ACTIVE') color = 'green';
  else if (status === 'SUPERSEDED') color = 'red';
  else if (status === 'REJECTED') color = 'red';
  
  return <Tag color={color}>{status || '-'}</Tag>;
}
