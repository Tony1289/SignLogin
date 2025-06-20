import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function LoginForm({ role }) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    securityCode: '',
  });

  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');

    const payload = {
      email: formData.email,
      password: formData.password,
      role: role,
    };

    if (role === 'admin') {
      payload.security_code = formData.securityCode;
    }

    try {
      const response = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || 'Login failed');
      }

      setMessage(result.message);

      if (result.role === 'admin') {
        localStorage.setItem('adminEmail', formData.email);
        navigate('/admin/dashboard');
      } else {
        localStorage.setItem('userEmail', formData.email);
        navigate('/user/dashboard');
      }
    } catch (error) {
      setMessage(error.message);
    }
  };

  return (
    <div style={styles.body}>
      <style>
        {`
          input::placeholder {
            color: white;
            opacity: 1;
          }

          input:-webkit-autofill,
          input:-webkit-autofill:hover,
          input:-webkit-autofill:focus,
          input:-webkit-autofill:active {
            -webkit-box-shadow: 0 0 0 30px transparent inset !important;
            -webkit-text-fill-color: white !important;
            transition: background-color 5000s ease-in-out 0s;
          }
        `}
      </style>

      <div style={styles.wrapper}>
        <form onSubmit={handleSubmit}>
          <h1 style={styles.title}>{role === 'admin' ? 'Admin' : 'User'} Login</h1>

          <div style={styles.inputBox}>
            <input
              type="email"
              name="email"
              placeholder="Email"
              required
              value={formData.email}
              onChange={handleChange}
              style={styles.input}
              autoComplete="email"
            />
          </div>

          <div style={styles.inputBox}>
            <input
              type="password"
              name="password"
              placeholder="Password"
              required
              value={formData.password}
              onChange={handleChange}
              style={styles.input}
              autoComplete="current-password"
            />
          </div>

          {role === 'admin' && (
            <div style={styles.inputBox}>
              <input
                type="password"
                name="securityCode"
                placeholder="Security Code"
                required
                value={formData.securityCode}
                onChange={handleChange}
                style={styles.input}
                autoComplete="off"
              />
            </div>
          )}

          <button type="submit" style={styles.button}>Login</button>

          {message && <p style={styles.message}>{message}</p>}
        </form>
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
  },
  title: {
    fontSize: '28px',
    textAlign: 'center',
    marginBottom: '20px',
  },
  inputBox: {
    width: '100%',
    margin: '15px 0',
  },
  input: {
    width: '100%',
    padding: '12px 15px',
    fontSize: '16px',
    background: 'transparent',
    border: '2px solid rgba(255, 255, 255, .2)',
    borderRadius: '40px',
    color: '#fff',
    outline: 'none',
    caretColor: '#fff',
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
    marginTop: '10px',
  },
  message: {
    marginTop: '10px',
    textAlign: 'center',
    color: '#ffcccc',
    fontWeight: 'bold',
  },
};

export default LoginForm;
