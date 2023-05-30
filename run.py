import streamlit as st
from stoch import proc, GMMHMM, result


st.header('Malicious Network activity detection using stochastic approach')
uploaded_file = st.file_uploader('Upload a pcap file', type=['pcap'])
if uploaded_file is not None:
    df = proc(uploaded_file)
    st.write('Scanning File for malicious activity. Please wait...')
    hmmpred = GMMHMM(df)
    hmmresult = result(hmmpred)
    details = str(round((hmmresult[0][hmmresult[1]])/(hmmresult[0][1]+hmmresult[0][0])*100,2))+"% " + "of the total traffic was found "+('benign' if hmmresult[1]==0 else 'malicious')
    st.write('Result is ready.')
    if hmmresult[-2] == "0":
        msz = "This file is Benign"
    else:
        msz = "This file contains Malware Traffic"
    st.write(msz)