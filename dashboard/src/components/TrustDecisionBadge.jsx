import React from 'react';
import { Tag, Tooltip } from 'antd';

export function TrustDecisionBadge({ status, reasonCode, reasonDesc }) {
  let color = 'default';
  let displayStatus = status || 'UNEVALUATED';
  
  if (status === 'TRUSTED') color = 'green';
  else if (status === 'CONDITIONALLY_ACCEPTED') color = 'blue';
  else if (status === 'REVIEW_REQUIRED') color = 'orange';
  else if (status === 'REJECTED') color = 'red';
  else if (status === 'UNTRUSTED') {
    color = 'red';
    displayStatus = 'REJECTED (legacy)';
  }

  const tag = <Tag color={color}>{displayStatus}</Tag>;

  if (reasonCode || reasonDesc) {
    return (
      <Tooltip title={`${reasonCode || ''}: ${reasonDesc || ''}`}>
        {tag}
      </Tooltip>
    );
  }
  return tag;
}
