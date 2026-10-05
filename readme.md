# Universal Log Pre-processing Framework

## Overview
- This project is proposed demo solution of SIH problem statement - SIH2026 PID-26156.
- It asks to create a log processing isolated program to process different log files from sources such as - Syslog, CEF, Fortinet, or from other vendors to a generalised data format which is ready to be used for SIEM or AI analytics.
- The program is purely written in python and is able to resolve the main problem of creating a generalised data format while also preserving the raw data.

## Features
- Currenlty, this program supports 4 parsers - Apache, Syslog, CEF, Fortinet.
- You can follow the 'running' instructions down below and can process as many log files you want.

### Scalability
- The architecture is scalable as -

    ![Architecture](docs/patterns_ss.png)

    - inside "patterns" dir you can add the regex patterns of any log file you want in this fashion : 

    ![Architecture](docs/pattern_ss.png)

    - remember the 'name' of this '.json' file as it will be used as the 'source' keyword for the whole program.

    - inside 'process/file_catg.py' file you can add the regex for log file detection by yourself.

    ![Architecture](docs/catg.png)

    - you can further add parser of your choice inside 'parsers/parser.py' file.

    ![Architecture](docs/parser.png)

    **In this way you can add lot of log file - detection, pattern matching, parser in less time and complexity.**

- The program follows the strict pipeline - 
    - read log file in memory
    - detect log file type
    - parse log file 
    - normalize log file into 'Universal Events' (data format)
    - write derived data of the generalised data format into 'output' dir.

- There are few sample log files and also the credit of their source is mentioned in the repository.
- All the converted log file data are stored into 'output' dir in the 'jsonl' format.
- A simple GUI has been implemented for more user friendly experience.

## Architecture

### Block Diagram

    **File pipelining**

```mermaid
flowchart LR
    A[Raw Log] --> B[Source Detection]
    B --> C[Parser]
    C --> D[Normalizer]
    D --> E[Validator]
    E --> F[Standardized Output]
```

    **UI pipelining**

```mermaid
flowchart TB
    A[MainWindow] --> B[CustomTaskBar]
    A --> C[Central Widget]

    B --> D[Select]
    B --> E[Process All]
    B --> F[Save All]

    C --> G[QVBoxLayout]

    G --> H[FileList]
    G --> I[MessageBox]

    H --> J[File Rows]

    J --> K[File Path]
    J --> L[Process / Save]
    J --> M[Remove]

    L --> N[Button State]
    N --> O[PROCESS]
    N --> P[SAVE]

    I --> Q[Operation Messages]

    D --> R[Select Event]
    E --> S[Process All Event]
    F --> T[Save All Event]

    R --> U[DataPacket]
    S --> U
    T --> U
    L --> U
    M --> U
```

    **Full Architecture**

```mermaid
flowchart TB
    %% UI

    A[User Interface] --> B[Select Files]
    A --> C[Process]
    A --> D[Process All]
    A --> E[Save]
    A --> F[Save All]
    A --> G[Remove]

    A --> H[FileList]
    A --> I[MessageBox]

    %% Communication

    B --> J[Event]
    C --> J
    D --> J
    E --> J
    F --> J
    G --> J

    J --> K[Connection]
    K --> L[NetworkManager]
    L --> M[DataPacket]
    M --> N[Receive]

    %% Gateway

    N --> O[Gateway]

    %% Pipeline

    O --> P[File Pipeline]

    P --> Q[Read File]
    Q --> R[Source Detection]
    R --> S[GenParser]

    %% Parsers

    S --> T[Apache Parser]
    S --> U[Syslog Parser]
    S --> V[CEF Parser]
    S --> W[Fortinet Parser]

    T --> X[Parse]
    U --> X
    V --> X
    W --> X

    X --> Y[Normalize]
    Y --> Z[Universal Events]

    %% Output

    Z --> AA[Serialize / Save]
    AA --> O

    %% Return to UI

    O --> AB[Operation Result]
    AB --> N

    N --> H
    N --> I
```

## Installation
- git clone this repo or,
- download the zip file and extract it.

## Running
inside the terminal run the program exactly in this format
```
python main.py
```

## Future Improvements
Currently, the presentable program is in early development so the following features have been decided to add in the later developments -
- switching to Dockerfile for complete air gapped environment
- improvising the "patterns/" dir to also include the detection regexes for larger scalability and so the program will be inherently independent from the user process