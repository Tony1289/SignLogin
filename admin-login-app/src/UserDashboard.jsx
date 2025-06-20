import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

function UserDashboard() {
  const [email, setEmail] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const storedEmail = localStorage.getItem('userEmail');
    if (!storedEmail) {
      navigate('/user/login');
    } else {
      setEmail(storedEmail);
    }
  }, [navigate]);

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:8000/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('userEmail');
      navigate('/');
    }
  };
  

  return (
    <div style={styles.body}>
      <div style={styles.wrapper}>
        <h1 style={styles.title}>Welcome, {email}</h1>
        <p style={styles.text}>You have successfully logged in as a user.</p>
        <button onClick={handleLogout} style={styles.button}>Logout</button>
      </div>
    </div>
  );
}

const styles = {
  body: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundImage:
      'url(https://img.playbook.com/IZSaaisbuPYRUSQYBZckzA61Px-1dJx2_5pGRp3N4dk/Z3M6Ly9wbGF5Ym9v/ay1hc3NldHMtcHVi/bGljLzRkZmUwYjQ2/LWRhNjAtNDQ2Yy1h/Y2UxLWM0ZTZkMGI3/NTdlMA)',
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    fontFamily: "'Poppins', sans-serif",
  },
  wrapper: {
    width: '420px',
    background: 'transparent',
    border: '2px solid rgba(255, 255, 255, .2)',
    backdropFilter: 'blur(20px)',
    boxShadow: '0 0 10px rgba(0 , 0 , 0 , .2)',
    color: '#fff',
    borderRadius: '10px',
    padding: '30px 40px',
    textAlign: 'center',
  },
  title: {
    fontSize: '28px',
    marginBottom: '20px',
  },
  text: {
    fontSize: '16px',
    marginBottom: '30px',
  },
  button: {
    width: '100%',
    padding: '12px',
    background: '#fff',
    border: 'none',
    borderRadius: '40px',
    color: '#333',
    fontSize: '16px',
    fontWeight: 'bold',
    cursor: 'pointer',
  },
};

export default UserDashboard;
