import React, { useState } from 'react';

function SignupForm({ role }) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    securityCode: '',
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.password !== formData.confirmPassword) {
      alert("Passwords don't match!");
      return;
    }

    try {
      const response = await fetch('http://localhost:8000/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          password: formData.password,
          role: role,
          security_code: role === 'admin' ? formData.securityCode : null,
        }),
      });

      const result = await response.json();

      if (!response.ok) throw new Error(result.detail || 'Signup failed');
      alert(result.message);
    } catch (error) {
      alert(`❌ ${error.message}`);
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
          <h1 style={styles.title}>{role === 'admin' ? 'Admin' : 'User'} Sign Up</h1>

          <div style={styles.inputBox}>
            <input
              type="text"
              name="username"
              placeholder="Username"
              value={formData.username}
              onChange={handleChange}
              required
              style={styles.input}
              autoComplete="username"
            />
          </div>

          <div style={styles.inputBox}>
            <input
              type="email"
              name="email"
              placeholder="Email"
              value={formData.email}
              onChange={handleChange}
              required
              style={styles.input}
              autoComplete="email"
            />
          </div>

          <div style={styles.inputBox}>
            <input
              type="password"
              name="password"
              placeholder="Password"
              value={formData.password}
              onChange={handleChange}
              required
              style={styles.input}
              autoComplete="new-password"
            />
          </div>

          <div style={styles.inputBox}>
            <input
              type="password"
              name="confirmPassword"
              placeholder="Confirm Password"
              value={formData.confirmPassword}
              onChange={handleChange}
              required
              style={styles.input}
              autoComplete="new-password"
            />
          </div>

          {role === 'admin' && (
            <div style={styles.inputBox}>
              <input
                type="password"
                name="securityCode"
                placeholder="Admin Security Code"
                value={formData.securityCode}
                onChange={handleChange}
                required
                style={styles.input}
                autoComplete="off"
              />
            </div>
          )}

          <button type="submit" style={styles.button}>
            Sign Up
          </button>
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
};

export default SignupForm;
