"""
A single test run won't cause any "user already registered" problem. But running it twice.. not so much.
Thoughts on how to fix..?

Current problems:
    - Cross runs can spawn a "user already registered" problem
    - No specifications regarding database field max size may cause issues when running tests for some students?
    - Should a test test that some method works with post and doesn't work with get (or vice-versa) at the same time?
    -

delete from post where author in (select id from user where email like "%legion%");
delete from user where email like "%legion%";
"""
import unittest
import requests
import argparse
import json
import random

parser = argparse.ArgumentParser(description='Twidder backend test suite. Assumes server is running on localhost')
parser.add_argument('--port', default=5000, help='The port where server is running')

args = parser.parse_args()

SERVER_DOMAIN = "http://127.0.0.1:%s" % args.port


class TestServerAuthenticationMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up our dummy user's info
        """
        cls.user_info = dict(email="fiery_archy@burninglegion.net", password="thetrueeredar", firstname="Archimonde",
                             familyname="the defiler", gender="male", city="Mac'Aree", country="Argus")

    def testSignUp(self):
        """
        Description: Registers a user in the database
        Input: Seven string values representing the following: e-mail, password, firstname, familyname, gender, city and country
        :return string in JSON format with success and message :
        """
        r = requests.get('%s/sign_up/' % SERVER_DOMAIN, params=self.user_info)
        # Is this ok? What if the students "accept" the get method but have their own custom method of denying it?
        self.assertNotEqual(r.status_code, 200)
        r = requests.post('%s/sign_up/' % SERVER_DOMAIN, data=self.user_info)
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

    def testSignIn(self):
        """
        Description: Authenticates the username by the provided password
        Input: Two string values representing the username (e-mail address) and password

        Returned data: A text string containing a randomly generated access token if the authentication is
        successful.
        :return A text string containing a randomly generated access token if the authentication is successful:
        """
        r = requests.get('%s/sign_in/' % SERVER_DOMAIN, params={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertNotEqual(r.status_code, 200)

        r = requests.post('%s/sign_in/' % SERVER_DOMAIN, data={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])
        self.assertTrue("token" in response['data'])


class TestServerAuthenticatedMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up our dummy user's info
        """
        cls.user_info = dict(email="@burninglegion.net", password="thetrueeredar", firstname="Archimonde",
                             familyname="the defiler", gender="male", city="Mac'Aree", country="Argus")
        cls.used_mails = [""]

    def setUp(self):
        """
        Set up a new account for this test and proceeds to sign in
        """
        letters = "abcdefghiklmnopqrstuvwwxyz"
        email_name = ""
        while email_name in self.used_mails:
            t = ""
            for i in range(5):
                t += letters[int(random.random() * len(letters))]
            email_name = t
        self.user_info["email"] = "%s%s" % (email_name,  self.user_info["email"])
        self.used_mails.append(email_name)

        r = requests.post('%s/sign_up/' % SERVER_DOMAIN, data=self.user_info)
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])
        r = requests.post('%s/sign_in/' % SERVER_DOMAIN,
                          data={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertEqual(r.status_code, 200)

        response = json.loads(r.text)
        self.assertTrue(response['success'])
        self.assertTrue("token" in response['data'])
        self.token = response['data']['token']

    def testChangePassword(self):
        """
        Description: Changes the password of the current user to a new one
        Input:
            - token: A string containing the access token of the current user
            - oldPassword: The old password of the current user
            - newPassword: The new password
        :return string in JSON format with success and message :
        """
        # Request password change to server
        r = requests.get('%s/change_password/' % SERVER_DOMAIN,
                          params=dict(token=self.token, old_password=self.user_info['password'], new_password="longlivesargeras"))
        self.assertNotEqual(r.status_code, 200)

        r = requests.post('%s/change_password/' % SERVER_DOMAIN,
                          data=dict(token=self.token, old_password=self.user_info['password'], new_password="longlivesargeras"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

        # Make sure the new password is the one used to sign in now
        r = requests.post('%s/sign_in/' % SERVER_DOMAIN, data={'email': self.user_info['email'], 'password': "longlivesargeras"})
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

    def testSignOut(self):
        """
        Description: Signs out a user from the system
        Input: A string containing the access token of the user requesting to sign out
        :return:
        """
        r = requests.get('%s/sign_out/' % SERVER_DOMAIN,
                          params=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)
        # sign_out(token)
        r = requests.post('%s/sign_out/' % SERVER_DOMAIN,
                          data=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

        r = requests.get('%s/get_user_data_by_token/' % SERVER_DOMAIN,
                         data=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertFalse(response['success'])

    def testGetUserDataByToken(self):
        """
        Description: retrieves the stored data for the user whom the passed token is issued for. The currently signed
        in user can use this method to retrieve all its own informatiom from the server
        Input: A string containing the access token of the current user
        :return A text string containing the following information- email, firstname, familyname, gender, city and country:
        """
        r = requests.post('%s/get_user_data_by_token/' % SERVER_DOMAIN,
                          data=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)

        r = requests.get('%s/get_user_data_by_token/' % SERVER_DOMAIN,
                         params=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])
        # Is this enough to assert that this response is ok, or do we want to check each key
        # self.assertEqual(len(response['data']), 6)

    def testGetUserDataByEmail(self):
        """
        Description: Retrieves the stored data for the user speciied by the passed e-mail address
        Input:
            - token: A string containing the access token of the current user
            - email: The email address of the user to retrieve data for
        :return A text string containing the following information- email, firstname, familyname, gender, city and country:
        """
        r = requests.post('%s/get_user_data_by_token/' % SERVER_DOMAIN,
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertNotEqual(r.status_code, 200)

        r = requests.get('%s/get_user_data_by_token/' % SERVER_DOMAIN,
                         params=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])
        # todo: uncomment this!!
        # self.assertEqual(len(response['data']), 6)

    def testGetUserMessagesByToken(self):
        """
        Description: retrieves the stored messages for the user whom the passed token is issued for. The currently signed in
        user can use this method to retrieve all its own messages from the server.
        Input: A string containing the access token of the current user.

        :return A text string containing all of the messages sent to the user:
        """
        # todo: post message here first
        r = requests.post('%s/get_user_messages_by_token/' % SERVER_DOMAIN,
                          data=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)

        r = requests.get('%s/get_user_messages_by_token/' % SERVER_DOMAIN,
                         params=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

    def testGetUserMessagesByEmail(self):
        """
        Description: Retrieves the stored messages for the user specified by the passed e-mail address
        Input:
            - token: a string containing the access token of the current user
            - email: the e-mail address of the user to retrieve messages for
        :return A text string containing all of the messages sent to the specified user:
        """
        r = requests.post('%s/get_user_messages_by_email/' % SERVER_DOMAIN,
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertNotEqual(r.status_code, 200)

        r = requests.get('%s/get_user_messages_by_email/' % SERVER_DOMAIN,
                         params=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

    def testPostMessage(self):
        """
        Description: tries to post a message to the wall of the user specified by the e-mail address
        Input:
            - token: a string containing the access token of the current user
            - message: The message to post
            - email: the e-mail address of the recipient
        :return:
        """
        r = requests.get('%s/post/' % SERVER_DOMAIN,
                         params=dict(token=self.token, email="fiery_archy@burninglegion.net", message="For the legion!"))
        self.assertNotEqual(r.status_code, 200)

        r = requests.post('%s/post/' % SERVER_DOMAIN,
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net", message="For the legion!"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.text)
        self.assertTrue(response['success'])

    @classmethod
    def tearDownClass(cls):
        # todo: Delete users somehow
        pass


def suite():
    suite = unittest.TestSuite()
    suite.addTest(TestServerAuthenticationMethods('testSignUp'))
    suite.addTest(TestServerAuthenticationMethods('testSignIn'))

    # suite.addTests(unittest.makeSuite(TestServerAuthenticatedMethods))
    suite.addTest(TestServerAuthenticatedMethods('testChangePassword'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserDataByToken'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserDataByEmail'))
    suite.addTest(TestServerAuthenticatedMethods('testSignOut'))
    suite.addTest(TestServerAuthenticatedMethods('testPostMessage'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserMessagesByToken'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserMessagesByEmail'))

    return suite

mySuit = suite()

if __name__ == '__main__':
    try:
        requests.get("%s/" % SERVER_DOMAIN)
        runner = unittest.TextTestRunner()
        runner.run(mySuit)
    except requests.exceptions.ConnectionError:
        print "Error: No backend found on this port. See help for usage."
