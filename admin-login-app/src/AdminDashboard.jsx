import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get('http://localhost:8000/admin/users')
      .then(response => {
        setUsers(response.data.users);
      })
      .catch(error => {
        console.error("Error fetching users:", error);
        alert("Session expired or unauthorized. Please login again.");
        navigate('/admin/login');
      });
  }, [navigate]);

  const handleLogout = async () => {
    const adminEmail = localStorage.getItem('adminEmail');
    try {
      await axios.post('http://localhost:8000/logout', {
        email: adminEmail,
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('token');
      localStorage.removeItem('adminEmail');
      navigate('/');
    }
  };
  

  return (
    <div style={styles.pageWrapper}>
      <div style={styles.container}>
        <h2 style={styles.title}>Admin Dashboard</h2>
        <div style={styles.tableWrapper}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Username</th>
                <th style={styles.th}>Email</th>
                <th style={styles.th}>Password</th>
                <th style={styles.th}>Login Date</th>
                <th style={styles.th}>Login Time</th>
                <th style={styles.th}>Logout Date</th>
                <th style={styles.th}>Logout Time</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user, index) => {
                const [loginDate, loginTime] = formatDateTime(user.login_time);
                const [logoutDate, logoutTime] = formatDateTime(user.logout_time);
                return (
                  <tr key={index} style={index % 2 === 0 ? styles.rowEven : styles.rowOdd}>
                    <td style={styles.td}>{user.username}</td>
                    <td style={styles.td}>{user.hashed_email}</td>
                    <td style={styles.td}>{user.hashed_password}</td>
                    <td style={styles.td}>{loginDate}</td>
                    <td style={styles.td}>{loginTime}</td>
                    <td style={styles.td}>{logoutDate}</td>
                    <td style={styles.td}>{logoutTime}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div style={styles.logoutWrapper}>
          <button onClick={handleLogout} style={styles.logoutButton}>Logout</button>
        </div>
      </div>
    </div>
  );
}

function formatDateTime(dateTimeString) {
  if (!dateTimeString) return ['—', '—'];
  const dateObj = new Date(dateTimeString);
  const date = dateObj.toLocaleDateString('en-GB'); // dd/mm/yyyy
  const time = dateObj.toLocaleTimeString('en-GB');
  return [date, time];
}

const styles = {
  pageWrapper: {
    backgroundColor: '#121212',
    minHeight: '100vh',
    padding: '40px 20px',
    display: 'flex',
    justifyContent: 'center',
    fontFamily: 'Inter, Segoe UI, sans-serif',
  },
  container: {
    width: '100%',
    maxWidth: '1100px',
    backgroundColor: '#1e1e1e',
    borderRadius: '12px',
    boxShadow: '0 8px 16px rgba(0, 0, 0, 0.5)',
    padding: '30px',
    color: '#ffffff'
  },
  title: {
    fontSize: '28px',
    fontWeight: 'bold',
    marginBottom: '20px',
    textAlign: 'center',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'center',
    fontSize: '14px',
  },
  th: {
    padding: '12px',
    backgroundColor: '#2c2c2c',
    color: '#ffffff',
    fontWeight: '600',
    borderBottom: '2px solid #444',
  },
  td: {
    padding: '10px',
    borderBottom: '1px solid #333',
    color: '#e0e0e0',
    wordBreak: 'break-word',
  },
  rowEven: {
    backgroundColor: '#1e1e1e',
  },
  rowOdd: {
    backgroundColor: '#2a2a2a',
  },
  logoutWrapper: {
    marginTop: '30px',
    textAlign: 'center',
  },
  logoutButton: {
    backgroundColor: '#d32f2f',
    color: '#ffffff',
    padding: '10px 24px',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: 'bold',
    fontSize: '16px'
  }
};

export default AdminDashboard;
