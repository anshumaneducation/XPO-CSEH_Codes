```
potentiometer ---> ADC Analog input
ADC Digital output ---> RPI GPIO 2(SDA) & 3(SCL)
RPI Through Internet ---> Firebase Cloud
Firebase Cloud ---> Website
```

### SDK Overview

To facilitate the integration and functionality of the system, the following SDKs are utilized:

#### 1. **Firebase SDK**
    - **Purpose**: Enables seamless communication with Firebase Cloud for storing and retrieving digital data.
    - **Features**:
      - Real-time database integration.
    - Hosting a web-based interface for real-time data visualization.
    - Integration with the `WEB` folder for additional resources and documentation:
        - The `WEB` folder contains supplementary files, such as HTML, CSS, and JavaScript, to support the frontend development of the project.
        - It includes pre-built templates and scripts for integrating Firebase Cloud data into the website.
        - Refer to the `WEB/README.md` file for detailed instructions on setting up and customizing the web interface.
      - Cloud storage for hosting files.
    - **Documentation**: [Firebase SDK Docs](https://firebase.google.com/docs)

#### 2. **Raspberry Pi GPIO Library**
    - **Purpose**: Provides control over the GPIO pins of the Raspberry Pi for interfacing with the ADC digital output.
    - **Features**:
      - Pin configuration (input/output).
      - Event detection for GPIO signals.
      - PWM signal generation.
    - **Documentation**: [Raspberry Pi GPIO Docs](https://gpiozero.readthedocs.io/)

#### 3. **ADC Driver SDK**
    - **Purpose**: Facilitates the conversion of analog signals from the potentiometer to digital signals.
    - **Features**:
      - High-resolution analog-to-digital conversion.
      - Support for multiple ADC channels.
    - **Documentation**: Refer to the specific ADC module's datasheet or SDK documentation.

#### 4. **Frontend Framework SDK**
    - **Purpose**: Used for building the website interface that displays data from Firebase Cloud.
    - **Features**:
      - Responsive design components.
      - Integration with Firebase for real-time updates.
    - **Examples**: React, Angular, or Vue.js.
    - **Documentation**: Refer to the chosen framework's official documentation.

These SDKs collectively enable the smooth operation of the IoT cloud system, from data acquisition to cloud storage and web visualization.