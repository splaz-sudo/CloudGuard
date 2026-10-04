import {
  BrowserRouter,
  Route,
  Routes,
} from "react-router-dom";

import "./App.css";

import Layout from "./components/Layout";
import { ScanProvider } from "./context/ScanContext";

import AttackPaths from "./pages/AttackPaths";
import Compare from "./pages/Compare";
import Compliance from "./pages/Compliance";
import Findings from "./pages/Findings";
import Identity from "./pages/Identity";
import Inventory from "./pages/Inventory";
import Network from "./pages/Network";
import Overview from "./pages/Overview";
import Remediations from "./pages/Remediations";
import Reports from "./pages/Reports";
import Scans from "./pages/Scans";


function App() {
  return (
    <BrowserRouter>
      <ScanProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route
              path="/"
              element={<Overview />}
            />

            <Route
              path="/scans"
              element={<Scans />}
            />

            <Route
              path="/compare"
              element={<Compare />}
            />

            <Route
              path="/inventory"
              element={<Inventory />}
            />

            <Route
              path="/attack-paths"
              element={<AttackPaths />}
            />

            <Route
              path="/identity"
              element={<Identity />}
            />

            <Route
              path="/network"
              element={<Network />}
            />

            <Route
              path="/findings"
              element={<Findings />}
            />

            <Route
              path="/remediations"
              element={<Remediations />}
            />

            <Route
              path="/compliance"
              element={<Compliance />}
            />

            <Route
              path="/reports"
              element={<Reports />}
            />
          </Route>
        </Routes>
      </ScanProvider>
    </BrowserRouter>
  );
}


export default App;