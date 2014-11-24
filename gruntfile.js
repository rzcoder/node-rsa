module.exports = function(grunt) {
    grunt.initConfig({
        jshint: {
            options: {
            },
            default: {
                files: {
                    src: ['src/**/*.js', '!src/libs/**/*']
                }
            },
            libs: {
                files: {
                    src: ['src/libs/**/*']
                }
            }
        },

        simplemocha: {
            options: {
                reporter: 'List'
            },
            all: { src: ['test/**/*.js'] }
        }
    });

    require('jit-grunt')(grunt, {
        'simplemocha': 'grunt-simple-mocha'
    });


    grunt.registerTask('lint', ['jshint:default']);
    grunt.registerTask('test', ['simplemocha']);

    grunt.registerTask('default', ['lint', 'test']);
}