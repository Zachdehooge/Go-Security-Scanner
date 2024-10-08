pipeline {
    agent any
    tools { go '1.23.1' 
            dockerTool "Docker"}

// Need to have Docker and GO plugins installed on Jenkins
    stages {

        stage('Unit Tests') {
            steps {
                script {
                    sh "go version"
                    // Running unit tests
                    sh '''
                    git clone https://github.com/Zachdehooge/Go-Security-Scanner/
                    cd Go-Security-Scanner
                    pwd
                    echo "Running unit tests..."
                    go test program_test.go
                    echo "Unit Tests Complete"
                    '''
                }
            }
        }
    } 
    post {
        always {
            cleanWs()
        }
    }
}
