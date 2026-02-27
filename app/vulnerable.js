// app/vulnerable.js — HIPAA Compliance Test for JavaScript
const logger = require('console');

function processPatientData(patientName, patientSSN, medicalConditions) {
    // HIPAA Violation: Logging PHI (SSN and Medical History)
    // Most security scanners and HIPAA-specific policies flag this
    console.log(`Processing patient: ${patientName}`);
    console.debug(`DEBUG: SSN ${patientSSN} - History: ${medicalConditions}`);
    AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    // Insecure transmission simulation
    const http = require('http');
    // HIPAA Violation: Unencrypted transmission of health data
    http.get('http://health-api.local/v1/patient-records', (res) => {
        // ...
    });
}
