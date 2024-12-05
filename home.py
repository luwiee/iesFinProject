import streamlit as st

# Main Page Design
st.markdown(
    """
    <style>
    .main-title {
        font-size: 36px;
        font-weight: bold;
        text-align: center;
        color: #ffffff; /* White color for better contrast */
        background-color: #2980b9; /* Dark blue background */
        padding: 10px; /* Padding for spacing */
        border-radius: 8px; /* Rounded corners */
    }
    .subtitle {
        font-size: 18px;
        text-align: center;
        color: #f39c12; /* Bright orange for contrast */
        margin-bottom: 20px;
    }
    .section-title {
        font-size: 20px;
        font-weight: bold;
        color: #1abc9c; /* Teal for section titles */
        margin-top: 20px;
        margin-bottom: 10px;
    }
    .names {
        font-size: 16px;
        color: #34495e; /* Dark gray for names */
        margin-bottom: 5px;
    }
    .footer {
        font-size: 14px;
        color: #7f8c8d; /* Light gray for footer text */
        text-align: center;
        margin-top: 30px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="main-title">Encryption Suite</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">(CS 412 - 9387)</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Final Project</div>', unsafe_allow_html=True)

# Add Project Members Section
st.markdown('<div class="section-title">Members:</div>', unsafe_allow_html=True)
st.markdown(
    """
    <div class="names">
    - CASIBANG, AIVEIN DYSTIN TOMAS<br>
    - DANGILAN, EZRHA LEIGH TOMAS<br>
    - ANTONIO, PETERJAN SOMERA<br>
    - VILLALOBOS, MAERVIN LLAGAS<br>
    - MIGUEL, LAWRENCE II TOMBAGA<br>
    - EMOCLING, MARIA SHEENA SHIELD PATTING<br>
    - ISABELO, DEREK BALAGEO
    </div>
    """,
    unsafe_allow_html=True,
)

# Add Adviser Section
st.markdown('<div class="section-title">Adviser:</div>', unsafe_allow_html=True)
st.markdown(
    """
    <div class="names">
    - Jan Michael Corton
    </div>
    """,
    unsafe_allow_html=True,
)

# Add Date Section
st.markdown('<div class="section-title">Date:</div>', unsafe_allow_html=True)
st.markdown(
    """
    <div class="names">
    - December 12, 2024
    </div>
    """,
    unsafe_allow_html=True,
)

# Footer or Introduction
st.markdown(
    """
    <div class="footer">
    Use the navigation sidebar to explore the AES, DES, and RSA encryption tools. Each page includes detailed functionality for encryption and decryption tasks.
    </div>
    """,
    unsafe_allow_html=True,
)
