import React, { useState, useCallback } from 'react';
import { YStack, XStack, Text, Select, Adapt, Sheet, Fieldset, Button, Spinner } from 'tamagui';
import { CalendarSearch, Check, ChevronDown, ChevronUp, Cpu } from '@tamagui/lucide-icons';
import { bgGreen, textBlack } from '../utils/colors';
import useUserStore from '../stores/userStore';
import useNavigationStore from '../stores/navigationStore';
import CustomButton from '../components/CustomButton';
import DatePicker from 'react-native-date-picker';
import { genMockPassportData } from '../../../common/src/utils/genMockPassportData';
import { countryCodes } from '../../../common/src/constants/constants';
import getCountryISO2 from "country-iso-3-to-2";
import { flag } from 'country-emoji';
const MockDataScreen: React.FC = () => {
  const [signatureAlgorithm, setSignatureAlgorithm] = useState("rsa_sha256");
  const listOfSignatureAlgorithms = ["rsa_sha1", "rsa_sha256", "rsapss_sha256"];

  const [dateOfBirthDatePicker, setDateOfBirthDatePicker] = useState<Date>(new Date(new Date().setFullYear(new Date().getFullYear() - 24)))
  const [dateOfExpiryDatePicker, setDateOfExpiryDatePicker] = useState<Date>(new Date(new Date().setFullYear(new Date().getFullYear() + 5)))
  const [dateOfBirthDatePickerIsOpen, setDateOfBirthDatePickerIsOpen] = useState(false)
  const [dateOfExpiryDatePickerIsOpen, setDateOfExpiryDatePickerIsOpen] = useState(false)
  const [nationality, setNationality] = useState("FRA")
  const [isGenerating, setIsGenerating] = useState(false)

  const castDate = (date: Date) => {
    return (date.toISOString().slice(2, 4) + date.toISOString().slice(5, 7) + date.toISOString().slice(8, 10)).toString();
  }
  const { toast } = useNavigationStore()

  const handleGenerate = useCallback(async () => {
    setIsGenerating(true);

    await new Promise(resolve => setTimeout(() => {
      const mockPassportData = genMockPassportData(signatureAlgorithm as "rsa_sha256" | "rsa_sha1" | "rsapss_sha256", nationality as keyof typeof countryCodes, castDate(dateOfBirthDatePicker), castDate(dateOfExpiryDatePicker));
      useUserStore.getState().registerPassportData(mockPassportData);
      useUserStore.getState().setRegistered(true);
      resolve(null);
    }, 0));

    toast.show("🤖", {
      message: "Passport generated",
      customData: {
        type: "success",
      },
    });

    await new Promise(resolve => setTimeout(resolve, 1000));
    useNavigationStore.getState().setSelectedTab("next");
  }, [signatureAlgorithm, nationality, dateOfBirthDatePicker, dateOfExpiryDatePicker]);

  return (
    <YStack p="$3" f={1} gap="$5">
      <Text ml="$1" fontSize={34} color={textBlack}><Text style={{ textDecorationLine: 'underline', textDecorationColor: bgGreen }}>Generate</Text> passport data</Text>
      <XStack ai="center" gap="$2" mt="$4">
        <Text f={1} miw="$12">
          Encryption
        </Text>
        <Select
          id="signature-algorithm"
          value={signatureAlgorithm}
          onValueChange={setSignatureAlgorithm}
          native
        >
          <Select.Trigger width={220} iconAfter={ChevronDown}>
            <Select.Value placeholder="Select algorithm" />
          </Select.Trigger>

          <Adapt when="sm" platform="touch">
            <Sheet
              modal
              dismissOnSnapToBottom
              animationConfig={{
                type: 'spring',
                damping: 20,
                mass: 1.2,
                stiffness: 250,
              }}
            >
              <Sheet.Frame>
                <Text fontSize="$8" p="$3">Encryption method</Text>
                <Sheet.ScrollView>
                  <Adapt.Contents />
                </Sheet.ScrollView>
              </Sheet.Frame>
              <Sheet.Overlay
                animation="lazy"
                enterStyle={{ opacity: 0 }}
                exitStyle={{ opacity: 0 }}
              />
            </Sheet>
          </Adapt>

          <Select.Content zIndex={200000}>
            <Select.ScrollUpButton ai="center" jc="center" pos="relative" w="100%" h="$3">
              <ChevronUp size={20} />
            </Select.ScrollUpButton>

            <Select.Viewport minWidth={200}>
              <Select.Group>
                {listOfSignatureAlgorithms.map((algorithm, index) => (
                  <Select.Item key={algorithm} index={index} value={algorithm}>
                    <Select.ItemText >{algorithm}</Select.ItemText>
                    <Select.ItemIndicator marginLeft="auto">
                      <Check size={16} />
                    </Select.ItemIndicator>
                  </Select.Item>
                ))}
              </Select.Group>
            </Select.Viewport>

            <Select.ScrollDownButton ai="center" jc="center" pos="relative" w="100%" h="$3">
              <ChevronDown size={20} />
            </Select.ScrollDownButton>
          </Select.Content>
        </Select>
      </XStack>


      <XStack ai="center" gap="$2" mt="$4">
        <Text f={1} miw="$12">
          Nationality
        </Text>
        <Select
          id="nationality"
          value={nationality}
          onValueChange={setNationality}
          native
        >
          <Select.Trigger width={220} iconAfter={ChevronDown}>
            <Select.Value placeholder="Select algorithm" />
          </Select.Trigger>

          <Adapt when="sm" platform="touch">
            <Sheet
              modal
              dismissOnSnapToBottom
              animationConfig={{
                type: 'spring',
                damping: 20,
                mass: 1.2,
                stiffness: 250,
              }}
            >
              <Sheet.Frame >
                <Text fontSize="$8" p="$3">Nationality</Text>
                <Sheet.ScrollView>
                  <Adapt.Contents />
                </Sheet.ScrollView>
              </Sheet.Frame>
              <Sheet.Overlay
                animation="lazy"
                enterStyle={{ opacity: 0 }}
                exitStyle={{ opacity: 0 }}
              />
            </Sheet>
          </Adapt>

          <Select.Content zIndex={200000}>
            <Select.ScrollUpButton ai="center" jc="center" pos="relative" w="100%" h="$3">
              <ChevronUp size={20} />
            </Select.ScrollUpButton>

            <Select.Viewport minWidth={200}>
              <Select.Group>
                {Object.keys(countryCodes).map((countryCode, index) => (
                  <Select.Item key={countryCode} index={index} value={countryCode}>
                    <Select.ItemText>{countryCodes[countryCode as keyof typeof countryCodes]} {flag(getCountryISO2(countryCode))}</Select.ItemText>
                    <Select.ItemIndicator marginLeft="auto">
                      <Check size={16} />
                    </Select.ItemIndicator>
                  </Select.Item>
                ))}
              </Select.Group>
            </Select.Viewport>

            <Select.ScrollDownButton ai="center" jc="center" pos="relative" w="100%" h="$3">
              <ChevronDown size={20} />
            </Select.ScrollDownButton>
          </Select.Content>
        </Select>
      </XStack>


      <Fieldset gap="$4" horizontal>
        <Text color={textBlack} width={160} justifyContent="flex-end" fontSize="$5">
          Date of birth
        </Text>
        <Text color={textBlack} f={1}>
          {dateOfBirthDatePicker ? dateOfBirthDatePicker.toISOString().slice(0, 10) : ''}
        </Text>
        <Button bg={bgGreen} onPress={() => setDateOfBirthDatePickerIsOpen(true)}
          borderRadius={"$10"}
        >
          <CalendarSearch />
        </Button>
        <DatePicker
          modal
          mode='date'
          open={dateOfBirthDatePickerIsOpen}
          date={dateOfBirthDatePicker || new Date()}
          onConfirm={(date) => {
            setDateOfBirthDatePickerIsOpen(false)
            setDateOfBirthDatePicker(date)
          }}
          onCancel={() => {
            setDateOfBirthDatePickerIsOpen(false)
          }}
        />
      </Fieldset>
      <Fieldset gap="$4" horizontal>
        <Text color={textBlack} width={160} justifyContent="flex-end" fontSize="$5">
          Date of expiry
        </Text>
        <Text color={textBlack} f={1}>
          {dateOfExpiryDatePicker ? dateOfExpiryDatePicker.toISOString().slice(0, 10) : ''}
        </Text>
        <Button bg={bgGreen} onPress={() => setDateOfExpiryDatePickerIsOpen(true)}
          borderRadius="$10"
        >
          <CalendarSearch />
        </Button>
        <DatePicker
          modal
          mode='date'
          open={dateOfExpiryDatePickerIsOpen}
          date={dateOfExpiryDatePicker || new Date()}
          onConfirm={(date) => {
            setDateOfExpiryDatePickerIsOpen(false)
            setDateOfExpiryDatePicker(date)
          }}
          onCancel={() => {
            setDateOfExpiryDatePickerIsOpen(false)
          }}
        />
      </Fieldset>

      <YStack f={1} />
      <CustomButton onPress={handleGenerate} text="Generate passport data" Icon={isGenerating ? <Spinner /> : <Cpu color={textBlack} />} isDisabled={isGenerating} />
    </YStack>
  );
};

export default MockDataScreen;