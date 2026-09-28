import {
  NavLink,
  Outlet,
} from "react-router-dom";


function Layout() {
  const navClass = ({
    isActive,
  }: {
    isActive: boolean;
  }) =>
    `nav-item ${isActive ? "active" : ""}`;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            CG
          </div>

          <div>
            <h1>CloudGuard</h1>
            <span>Cloud Security</span>
          </div>
        </div>

        <nav className="navigation">
          <NavLink
            to="/"
            end
            className={navClass}
          >
            Overview
          </NavLink>

          <NavLink
            to="/inventory"
            className={navClass}
          >
            Inventory
          </NavLink>

          <NavLink
            to="/attack-paths"
            className={navClass}
          >
            Attack Paths
          </NavLink>

          <NavLink
            to="/identity"
            className={navClass}
          >
            Identity
          </NavLink>

          <NavLink
            to="/network"
            className={navClass}
          >
            Network
          </NavLink>

          <NavLink
            to="/findings"
            className={navClass}
          >
            Findings
          </NavLink>

          <NavLink
            to="/compliance"
            className={navClass}
          >
            Compliance
          </NavLink>

          <NavLink
            to="/reports"
            className={navClass}
          >
            Reports
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />

          <div>
            <strong>
              Analysis Engine
            </strong>

            <span>
              Local simulation
            </span>
          </div>
        </div>
      </aside>

      <main className="dashboard">
        <Outlet />
      </main>
    </div>
  );
}


export default Layout;