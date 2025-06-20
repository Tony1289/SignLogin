import React from 'react';
import { useNavigate } from 'react-router-dom';

function RoleSelector() {
  const navigate = useNavigate();

  const handleSelect = (role, action) => {
    navigate(`/${role}/${action}`);
  };

  return (
    <div style={styles.body}>
      <style>
        {`
          button:hover {
            opacity: 0.9;
          }
        `}
      </style>
      <h1 style={styles.heading}>Select Your Role</h1>
      <div style={styles.cardContainer}>
        <div style={styles.card}>
          <h2 style={styles.cardTitle}>User</h2>
          <button style={styles.button} onClick={() => handleSelect('user', 'signup')}>
            Sign Up as User
          </button>
          <button style={styles.button} onClick={() => handleSelect('user', 'login')}>
            Login as User
          </button>
        </div>

        <div style={styles.card}>
          <h2 style={styles.cardTitle}>Admin</h2>
          <button style={styles.button} onClick={() => handleSelect('admin', 'signup')}>
            Sign Up as Admin
          </button>
          <button style={styles.button} onClick={() => handleSelect('admin', 'login')}>
            Login as Admin
          </button>
        </div>
      </div>
    </div>
  );
}

const styles = {
  body: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundImage:
      'url(https://img.playbook.com/IZSaaisbuPYRUSQYBZckzA61Px-1dJx2_5pGRp3N4dk/Z3M6Ly9wbGF5Ym9v/ay1hc3NldHMtcHVi/bGljLzRkZmUwYjQ2/LWRhNjAtNDQ2Yy1h/Y2UxLWM0ZTZkMGI3/NTdlMA)',
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    fontFamily: "'Poppins', sans-serif",
    padding: '40px 20px',
    textAlign: 'center',
    color: '#fff',
  },
  heading: {
    fontSize: '32px',
    marginBottom: '40px',
  },
  cardContainer: {
    display: 'flex',
    justifyContent: 'center',
    flexWrap: 'wrap',
    gap: '30px',
  },
  card: {
    background: 'transparent',
    border: '2px solid rgba(255, 255, 255, .2)',
    backdropFilter: 'blur(20px)',
    borderRadius: '10px',
    padding: '30px',
    width: '260px',
    boxShadow: '0 0 10px rgba(0, 0, 0, 0.2)',
  },
  cardTitle: {
    fontSize: '24px',
    marginBottom: '20px',
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
    marginBottom: '10px',
  },
};

export default RoleSelector;
