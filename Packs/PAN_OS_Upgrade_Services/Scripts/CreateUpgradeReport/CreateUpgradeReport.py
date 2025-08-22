import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

def header(current_value, stage):
    '''
    Appends the report header to the current value based on the upgrade stage
    '''
    if current_value:
        current_value += '\n\n-----\n\n'

    current_value += f'# Upgrade Assurance Report'
    if stage:
        current_value += f' ({stage})\n\n'
    else:
        current_value += '\n\n'

    return current_value

def add_passed(current_value, report_type, passed):
    '''
    Appends the passed tests to the report
    '''
    current_value += f'## {report_type} checks PASSED\n\n'

    if passed:
        for test in passed:
            current_value += f' * ✅ {test}\n'
    else:
        current_value += '❌ All tests failed! ❌\n'

    current_value += '\n'
    return current_value

def add_failed(current_value, report_type, failed):
    '''
    Appends the failed tests to the report
    '''
    current_value += f'## {report_type} checks FAILED\n\n'

    if failed:
        for test in failed:
            current_value += f' * ❌ {test}\n'
    else:
        current_value += '✅ All Tests Passed! ✅\n'

    current_value += '\n'
    return current_value

def add_results(current_value, results, result_key, test_name):
    '''
    Given the current value, add the results based on the true/false value of result_key
    '''
    if results:
        failed_results = [item.get('Test') for item in results if not item.get(result_key)]
        current_value = add_failed(current_value, test_name, failed_results)
        passed_results = [item.get('Test') for item in results if item.get(result_key)]
        current_value = add_passed(current_value, test_name, passed_results)

    return current_value

''' MAIN FUNCTION '''

def main():
    try:
        args = demisto.args()
        read = args.get('readiness_results')
        snap = args.get('snapshot_results')
        existing_report = args.get('existing_report', '')
        stage = args.get('stage')

        report = header(existing_report, stage)

        # Get the readiness test results if provided
        if read:
            passed_read_tests = [item.get('Test') for item in read if item.get('state')]
            failed_read_tests = [item.get('Test') for item in read if not item.get('state')]
            report = add_failed(report, 'Readiness Test', failed_read_tests)
            report = add_passed(report, 'Readiness Test', passed_read_tests)

        # Get the snapshot comparison test results if provided
        if snap:
            passed_snap_tests = [item.get('test') for item in snap if item.get('passed')]
            failed_snap_tests = [item.get('test') for item in snap if not item.get('passed')]
            report = add_failed(report, 'Snapshot Comparison', failed_snap_tests)
            report = add_passed(report, 'Snapshot Comparison', passed_snap_tests)

        return_results(CommandResults(
                outputs_prefix="UpgradeReport",
                outputs=report,
                ignore_auto_extract=True,
                readable_output=report,
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


