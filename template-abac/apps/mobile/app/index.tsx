import { StyleSheet, Text, View } from 'react-native';

export default function LocalDashboard() {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Kalekit — Local</Text>
      <Text style={styles.body}>
        The app a verified Local uses to accept assignments, run the viewing, and
        submit the report. Push notifications and background photo upload are why
        this is native, not web.
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24, gap: 12 },
  title: { fontSize: 24, fontWeight: '700' },
  body: { fontSize: 15, textAlign: 'center', color: '#4b5563' },
});
