// 角色与权限 —— 与平台后端 portal_server.py 的 WRITE_ROLES 对齐
// PRD §11 四角色：admin 技术负责人 / analyst 安全分析师 / asset_admin 资产管理员 / ops 运维值班
export const ROLE_LABEL = {
  admin: "技术负责人",
  analyst: "安全分析师",
  asset_admin: "资产管理员",
  ops: "运维值班",
};

// 各上游"写操作"允许的角色
const WRITE = {
  os: ["admin"],
  corr: ["admin"],
  asset: ["admin", "asset_admin"],
  soar: ["admin", "ops"],
  traffic: ["admin", "ops", "analyst"], // 流量查询/导出为只读 GET，这里仅占位
};

// 前端仅用于"隐藏无权限按钮"，真正的鉴权由后端执行
export function canWrite(key) {
  const u = window.__ssp_user__;
  if (!u) return false;
  return (WRITE[key] || ["admin"]).includes(u.role);
}
