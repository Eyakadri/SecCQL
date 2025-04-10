import React from 'react';
import { BrowserRouter as Router, Route, Switch, Link } from 'react-router-dom';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import Scans from './pages/Scans';
import Reports from './pages/Reports';
import './styles/App.css';

function App() {
    return (
        <Router>
            <div className="App">
                <Navbar />
                <Switch>
                    <Route path="/" exact component={Home} />
                    <Route path="/scans" component={Scans} />
                    <Route path="/reports" component={Reports} />
                    <Route path="*">
                        <div>404 - Page Not Found</div>
                    </Route>
                </Switch>
            </div>
        </Router>
    );
}

export default App;